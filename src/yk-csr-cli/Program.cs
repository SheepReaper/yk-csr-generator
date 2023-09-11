using System.CommandLine;
using GenerateYKCSR;

var rootCommand = new RootCommand("Generates a Certificate Signing Request (CSR) using a private key from a YubiKey device.");

GenerateCSRCommand.Options.ForEach(om => rootCommand.Add(om.Option));

rootCommand.SetHandler(GenerateCSRCommand.ExecuteAsync, new GenerateCSRCommand.Binder([.. GenerateCSRCommand.Options]));

await rootCommand.InvokeAsync(args);