namespace Neo4j.AspNet.Identity
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using Microsoft.AspNet.Identity;
    using Newtonsoft.Json;
    using Newtonsoft.Json.Linq;

    public class Neo4jUserJsonConverter : JsonConverter
    {
        public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
        {

            var user = value as ApplicationUser;
            if (user == null)
                return;

            var jToken = JToken.FromObject(value);
            if (jToken.Type != JTokenType.Object)
            {
                jToken.WriteTo(writer);
            }
            else
            {
                var jObject = RemoveProperty((JObject)jToken, "Logins");
                jObject = RemoveProperty(jObject, "Claims");
                jObject = RemoveProperty(jObject, "Roles");

                RemoveNullProperties(jObject);

                //Write away!
                jObject.WriteTo(writer);
            }
        }

        private static void RemoveNullProperties(JObject jObject)
        {
            var propertiesToRemove = (from property in jObject.Properties() where property.Value.Type == JTokenType.Null select property.Name).ToList();
            foreach (var property in propertiesToRemove)
                jObject.Remove(property);
        }

        private static bool IsNullOrEmpty(JToken token)
        {
            return (token == null) ||
                   (token.Type == JTokenType.Array && !token.HasValues) ||
                   (token.Type == JTokenType.Object && !token.HasValues) ||
                   (token.Type == JTokenType.String && token.ToString() == String.Empty) ||
                   (token.Type == JTokenType.Null);
        }

        private static JObject RemoveProperty(JObject jObject, string propertyName)
        {
            //Store original token in a temporary var
            var intString = jObject.Property(propertyName);
            //Remove original from the JObject
            jObject.Remove(propertyName);
            //Add a new 'InsString' property 'stringified'
            jObject.Add(propertyName, intString.Value.ToString());
            return jObject;
        }

        public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
        {
            if (objectType != typeof(ApplicationUser))
                return null;

            //Load our object
            var jObject = JObject.Load(reader);

            var claims = ExtractProperty<List<IdentityUserClaim>>(jObject, "Claims");
            var logins = ExtractProperty<List<UserLoginInfo>>(jObject, "Logins");
            var roles = ExtractProperty<List<string>>(jObject, "Roles");

            //The output
            var output = new ApplicationUser();
            //Deserialize all the normal properties
            try
            {
                if (serializer == null)
                    serializer = new JsonSerializer();
                serializer.Populate(jObject.CreateReader(), output);
            }
            catch (Exception ex)
            {
                int i = 0;
            }

            //Add our dictionary
            output.Claims = claims;
            output.Logins = logins;
            output.Roles = roles;

            //return
            return output;
        }

        private static T ExtractProperty<T>(JObject jObject, string propertyName)
        {
            var token = jObject.Property(propertyName).Value;
            //Remove it so it's not deserialized by Json.NET
            jObject.Remove(propertyName);

            //Get the dictionary ourselves and deserialize
            var output = JsonConvert.DeserializeObject<T>(token.ToString());
            return output;
        }

        public override bool CanConvert(Type objectType)
        {
            return objectType == typeof(ApplicationUser);
        }
    }
}