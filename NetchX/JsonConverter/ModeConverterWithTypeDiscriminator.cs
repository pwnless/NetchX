using System.Text.Json;
using System.Text.Json.Serialization;
using NetchX.Models.Modes;
using NetchX.Models.Modes.ProcessMode;
using NetchX.Models.Modes.ShareMode;
using NetchX.Models.Modes.TunMode;

namespace NetchX.JsonConverter;

public class ModeConverterWithTypeDiscriminator : JsonConverter<Mode>
{
    public override Mode? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        var jsonElement = JsonSerializer.Deserialize<JsonElement>(ref reader);

        var modeTypePropertyName = JsonNamingPolicy.CamelCase.ConvertName(nameof(Mode.Type));
        if (!jsonElement.TryGetProperty(modeTypePropertyName, out var modeTypeToken))
            throw new JsonException();

        var modeTypeEnum = modeTypeToken.ValueKind switch
        {
            JsonValueKind.Number => (ModeType)modeTypeToken.GetInt32(),
            JsonValueKind.String => Enum.Parse<ModeType>(modeTypeToken.GetString()!),
            _ => throw new JsonException()
        };

        var modeType = modeTypeEnum switch
        {
            ModeType.ProcessMode => typeof(Redirector),
            ModeType.TunMode => typeof(TunMode),
            ModeType.ShareMode => typeof(ShareMode),
            _ => throw new ArgumentOutOfRangeException()
        };

        return (Mode?)jsonElement.Deserialize(modeType, options);
    }

    public override void Write(Utf8JsonWriter writer, Mode value, JsonSerializerOptions options)
    {
        JsonSerializer.Serialize<object>(writer, value, options);
    }
}