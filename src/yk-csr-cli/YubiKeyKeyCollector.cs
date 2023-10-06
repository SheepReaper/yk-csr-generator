using System.Reflection.Metadata;
using System.Text;
using Yubico.YubiKey;

namespace GenerateYKCSR;

public class YubiKeyKeyCollector
{
    private static bool VerifyPivPinHandler(KeyEntryData ked)
    {
        Console.Clear();

        if (ked.IsRetry)
        {
            Console.WriteLine("Invalid PIN. Please try again.");
            Console.WriteLine($"{ked.RetriesRemaining} retries remaining before PIN is locked.");
        }

        var pinEntry = string.Empty;
        int[] validPinLengths = [6, 7, 8];

        do
        {
            Console.Write("Please input your PIV PIN (C to cancel): ");

            pinEntry = Console.ReadLine();

            if (!validPinLengths.Contains(pinEntry!.Length))
            {
                Console.WriteLine("PIN length must be 6, 7, or 8");
                continue;
            }

            if (pinEntry.Equals("c", StringComparison.InvariantCultureIgnoreCase)) return false;
        } while (!validPinLengths.Contains(pinEntry.Length));

        ked.SubmitValue(Encoding.Default.GetBytes(pinEntry));

        return true;
    }

    private static readonly Dictionary<KeyEntryRequest, Func<KeyEntryData, bool>> requestHandlerMap = new() {
        {KeyEntryRequest.Release, (_) => true},
        {KeyEntryRequest.VerifyPivPin, VerifyPivPinHandler}
    };

    public YubiKeyKeyCollector(Handle parentWindow) { }

    public YubiKeyKeyCollector() { }

    public static bool KeyCollectorDelegate(KeyEntryData keyEntryData)
    {
        return requestHandlerMap.TryGetValue(keyEntryData.Request, out var handler)
            ? handler(keyEntryData)
            : throw new ArgumentException("Unsupported key entry request");
    }
}