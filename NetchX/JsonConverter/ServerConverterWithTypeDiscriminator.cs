using System.Text.Json;
using System.Text.Json.Serialization;
using NetchX.Models;
using NetchX.Utils;

namespace NetchX.JsonConverter;

public class ServerConverterWithTypeDiscriminator : JsonConverter<Server>
{
    public override Server Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        var jsonElement = JsonSerializer.Deserialize<JsonElement>(ref reader);
        var typeName = jsonElement.GetProperty("Type").GetString()!;
        if (typeName.Equals("SSR", StringComparison.OrdinalIgnoreCase))
            return jsonElement.Deserialize<RemovedShadowsocksRServer>(options)!;

        var type = ServerHelper.GetTypeByTypeName(typeName);
        return (Server)jsonElement.Deserialize(type, options)!;
    }

    public override void Write(Utf8JsonWriter writer, Server value, JsonSerializerOptions options)
    {
        JsonSerializer.Serialize<object>(writer, value, options);
    }
}