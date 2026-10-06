using System.Globalization;
using System.Security.Cryptography;
using System.Text;

return Run(args);

static int Run(string[] args)
{
    if (args.Length == 0 || args is ["--help"] or ["-h"])
    {
        Console.WriteLine("""
            授权码生成工具 (.NET 8)
              keygen <私钥文件路径>                 生成加密的 P-256 私钥，输出公钥 X/Y
              public <私钥文件路径>                 再次输出公钥 X/Y
              issue <私钥文件路径> <客户名> <yyyyMMdd> <机器标识或*>

            示例（从仓库根目录执行；请将私钥保存在仓库外）：
              dotnet run --project tools/LicenseGenerator -- keygen /安全目录/channel.pem
              dotnet run --project tools/LicenseGenerator -- public /安全目录/channel.pem
              dotnet run --project tools/LicenseGenerator -- issue /安全目录/channel.pem "客户" 20991231 "*"

            密码在运行时输入，不要写入命令参数。私钥以加密 PKCS#8 PEM 保存，不会被覆盖。
            替换验证端 ECPoint 的 X/Y 十六进制值，Curve 保持 nistP256。
            更换公钥后旧授权码失效；不要把私钥或密码分发到验证端。
            Machine 为 * 表示通用码，否则填写目标机器 MachineHash() 的 16 位十六进制结果。
            日期按验证端本地时间判断，到期当天有效。客户名不能含 | 或控制字符。
            输出为 MCH6 + 无填充 Base32(UTF8 内容 + 64 字节 P1363 签名)。
            """);
        return 0;
    }

    try
    {
        switch (args)
        {
            case ["keygen", var path]:
                GenerateKey(path);
                break;
            case ["public", var path]:
                using (var key = LoadKey(path))
                    PrintPublicKey(key);
                break;
            case ["issue", var path, var customer, var expire, var machine]:
                Issue(path, customer, expire, machine);
                break;
            default:
                throw new ArgumentException("参数不正确，请使用 --help 查看用法。");
        }
        return 0;
    }
    catch (Exception ex) when (ex is ArgumentException or IOException or
                               UnauthorizedAccessException or CryptographicException)
    {
        Console.Error.WriteLine($"失败：{ex.Message}");
        return 1;
    }
}

static void GenerateKey(string path)
{
    if (File.Exists(path))
        throw new IOException("私钥文件已存在，不会覆盖。");

    string password = ReadPassword("新私钥密码（至少 12 个字符）：");
    if (password.Length < 12)
        throw new ArgumentException("密码至少需要 12 个字符。");
    if (password != ReadPassword("再次输入密码："))
        throw new ArgumentException("两次密码不一致。");

    using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    string pem = key.ExportEncryptedPkcs8PrivateKeyPem(password,
        new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 200_000));
    var options = new FileStreamOptions
    {
        Mode = FileMode.CreateNew,
        Access = FileAccess.Write,
        Share = FileShare.None
    };
    if (!OperatingSystem.IsWindows())
        options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;

    using (var stream = new FileStream(path, options))
    using (var writer = new StreamWriter(stream, new UTF8Encoding(false)))
        writer.Write(pem);

    Console.Error.WriteLine("加密私钥已保存。请备份私钥及密码，并限制文件访问权限。");
    PrintPublicKey(key);
}

static ECDsa LoadKey(string path)
{
    string pem = File.ReadAllText(path);
    string password = ReadPassword("私钥密码：");
    var key = ECDsa.Create();
    try
    {
        key.ImportFromEncryptedPem(pem, password);
        if (key.ExportParameters(false).Curve.Oid.Value != ECCurve.NamedCurves.nistP256.Oid.Value)
            throw new ArgumentException("私钥必须使用 nistP256 曲线。");
        return key;
    }
    catch
    {
        key.Dispose();
        throw;
    }
}

static void PrintPublicKey(ECDsa key)
{
    var parameters = key.ExportParameters(false);
    Console.WriteLine($"X = {Convert.ToHexString(parameters.Q.X!)}");
    Console.WriteLine($"Y = {Convert.ToHexString(parameters.Q.Y!)}");
}

static void Issue(string path, string customer, string expire, string machine)
{
    if (string.IsNullOrWhiteSpace(customer) || customer.Contains('|') || customer.Any(char.IsControl))
        throw new ArgumentException("客户名不能为空，也不能含 | 或控制字符。");
    if (expire.Length != 8 || expire.Any(c => c is < '0' or > '9') ||
        !DateTime.TryParseExact(expire, "yyyyMMdd", CultureInfo.InvariantCulture,
            DateTimeStyles.None, out var date) || date.Date < DateTime.Now.Date)
        throw new ArgumentException("到期日期必须是未过期的有效 yyyyMMdd 日期。");
    if (machine != "*" && (machine.Length != 16 || machine.Any(c => !Uri.IsHexDigit(c))))
        throw new ArgumentException("机器标识必须是 * 或 16 位十六进制 MachineHash。");

    using var key = LoadKey(path);
    string nonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
    byte[] payload = Encoding.UTF8.GetBytes(
        $"MCHL1|{customer}|{expire}|{machine.ToUpperInvariant()}|{nonce}");
    byte[] signature = key.SignData(payload, HashAlgorithmName.SHA256,
        DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    if (signature.Length != 64 || !key.VerifyData(payload, signature, HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
        throw new CryptographicException("签名自检失败。");

    byte[] data = new byte[payload.Length + signature.Length];
    payload.CopyTo(data, 0);
    signature.CopyTo(data, payload.Length);
    Console.WriteLine("MCH6" + Base32Encode(data));
}

static string Base32Encode(byte[] data)
{
    const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    var output = new StringBuilder();
    int buffer = 0;
    int bits = 0;
    foreach (byte value in data)
    {
        buffer = (buffer << 8) | value;
        bits += 8;
        while (bits >= 5)
        {
            bits -= 5;
            output.Append(alphabet[(buffer >> bits) & 31]);
        }
        buffer &= (1 << bits) - 1;
    }
    if (bits > 0)
        output.Append(alphabet[(buffer << (5 - bits)) & 31]);
    return output.ToString();
}

static string ReadPassword(string prompt)
{
    Console.Error.Write(prompt);
    if (Console.IsInputRedirected)
    {
        string result = Console.ReadLine() ?? throw new ArgumentException("未提供密码。");
        Console.Error.WriteLine();
        return result;
    }

    var password = new StringBuilder();
    while (true)
    {
        var key = Console.ReadKey(intercept: true);
        if (key.Key == ConsoleKey.Enter)
        {
            Console.Error.WriteLine();
            return password.ToString();
        }
        if (key.Key == ConsoleKey.Backspace)
        {
            if (password.Length > 0)
                password.Length--;
        }
        else if (!char.IsControl(key.KeyChar))
            password.Append(key.KeyChar);
    }
}
