using HtmlAgilityPack;
using Newtonsoft.Json;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

public class VpnService:IDisposable
{
    private const string LoginAuthUrl = "https://webvpn.zju.edu.cn/login";
    private const string LoginPswUrl = "https://webvpn.zju.edu.cn/do-login";
    public HttpClient client;
    public CookieContainer Jar;
    public bool Logined = false;
    public bool IsVpnEnabled = false;
    public bool AutoDirect = true;
    private bool _disposed = false;
    public Cookie Ticket => Jar.GetCookies(new Uri("https://webvpn.zju.edu.cn"))["wengine_vpn_ticketwebvpn_zju_edu_cn"] ?? new Cookie();
    public VpnService()
    {
        Jar = new CookieContainer();
        var handler = new HttpClientHandler
        {
            AllowAutoRedirect = AutoDirect,
            CookieContainer = Jar,
            UseCookies = true,
            AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate

        };

        client = new HttpClient(handler);
        client.DefaultRequestHeaders.Add("Referer", "https://webvpn.zju.edu.cn/");
        client.DefaultRequestHeaders.Connection.ParseAdd("keep-alive");
        client.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0");
    }
    public async Task<string> LoginAsync(string username,string password,CancellationToken cts = default)
    {
        try
        {
            var res = await client.GetAsync(LoginAuthUrl);
            if (res.StatusCode == HttpStatusCode.OK)
            {
                var html = await res.Content.ReadAsStringAsync();
                var param = GetRandCode(html);
                string encrpted_password = BuildPassword("wrdvpnisawesome!",password,26);
                var formData = new Dictionary<string, string>
            {
                {"_csrf", param.csrf},
                {"auth_type", param.auth_type},
                {"sms_code", ""},
                {"captcha","" },
                {"needCaptcha", "false"},
                {"captcha_id", param.captcha},
                {"username",username},
                {"password",encrpted_password }
            };
                var content = new FormUrlEncodedContent(formData);
                var login_res = await client.PostAsync(LoginPswUrl, content);
                Console.WriteLine(login_res.StatusCode);
                Console.WriteLine();
                string text = await login_res.Content.ReadAsStringAsync();
                if (ParseLoginResult(text))
                {
                    Logined = true;
                    return "1";
                }
                else
                {
                    return "0";
                }
            }
            else
            {
                return "404:获取CSRF失败";
            }
        }
        catch(Exception ex)
        {
            return $"404:{ex.Message}";
        }
    }

    public async Task<byte[]> GetByteArrayAsync(string url, CancellationToken cts = default)
    {
        if (!Logined)
            throw new InvalidOperationException("Not logged in");

        string targetUrl = IsVpnEnabled ? ConvertUrl(url) : url;
        try
        {
            var res = await client.GetAsync(targetUrl);
            if (res.IsSuccessStatusCode)
            {
                return await res.Content.ReadAsByteArrayAsync();
            }
        }
        catch { }
        return null;

    }
    public async Task<HttpResponseMessage> GetAsync(string url, CancellationToken cts = default)
    {
        var res = await SendRequestAsync(HttpMethod.Get, url, null);
        return res;
    }

    public async Task<HttpResponseMessage> PostAsync(string url, HttpContent content, CancellationToken cts = default)
    {
        var res = await SendRequestAsync(HttpMethod.Post, url, content); 
        return res;
    }
    public async Task<HttpResponseMessage> SendAsync(string url, HttpRequestMessage request, CancellationToken cts = default)
    {
        if (!Logined && IsVpnEnabled)
            throw new Exception("WebVPN未连接");
        string targetUrl = IsVpnEnabled ? ConvertUrl(url) : url;
        request.RequestUri = new Uri(targetUrl);
        var res = await client.SendAsync(request);
        return res;
    }
    public async Task<HttpResponseMessage> DeleteAsync(string url, CancellationToken cts = default)
    {
        if (!Logined && IsVpnEnabled)
            throw new Exception("WebVPN未连接");
        string targetUrl = IsVpnEnabled ? ConvertUrl(url) : url;
        using var request = new HttpRequestMessage(HttpMethod.Delete, targetUrl);
        var res = await client.SendAsync(request);
        return res;
    }
    public async Task<HttpResponseMessage> PutAsync(string url, StringContent content, CancellationToken cts = default)
    {
        if (!Logined && IsVpnEnabled)
            throw new Exception("WebVPN未连接");
        string targetUrl = IsVpnEnabled ? ConvertUrl(url) : url;
        using var request = new HttpRequestMessage(HttpMethod.Put, targetUrl);
        request.Content = content;
        var res = await client.SendAsync(request);
        return res;
    }
    private async Task<HttpResponseMessage> SendRequestAsync(HttpMethod method, string url,
        HttpContent content, CancellationToken cts = default)
    {
        if (!Logined && IsVpnEnabled)
            throw new Exception("WebVPN未连接");
        string targetUrl = IsVpnEnabled ? ConvertUrl(url) : url;
        using var request = new HttpRequestMessage(method, targetUrl);
        if (method == HttpMethod.Post && content != null)
        {
            request.Content = content;
        }
        var res = await client.SendAsync(request);
        return res;
    }
    /// <summary>
    /// 标准URL转换函数
    /// </summary>
    /// <param name="origin"></param>
    /// <returns></returns>
    public static string ConvertUrl(string origin)
    {
        var uri = new Uri(origin);
        string scheme=uri.Scheme;
        int port = uri.Port;
        string host=uri.Host;
        bool is_special_port = port > 0 &&
            !(uri.Scheme == "http" && port == 80) &&
            !(uri.Scheme == "https" && port == 443);
        string property =is_special_port? $"{scheme}-{port}":scheme;
        string vpn_scheme = "https";
        string vpn_host = "webvpn.zju.edu.cn";
        string[] pathSegments = new[]
        {
            property,
            BuildPassword("wrdvpnisthebest!",host,24)
        };
        var builder = new UriBuilder(vpn_scheme, vpn_host);
        var sb = new System.Text.StringBuilder();
        foreach (var seg in pathSegments)
            sb.Append('/').Append(Uri.EscapeDataString(seg));
        builder.Path = sb.ToString();
        Uri fullUri = builder.Uri;
        return fullUri.ToString();
    }
    /// <summary>
    /// 检查是否内网环境。
    /// </summary>
    /// <param name="UseVpn"></param>
    /// <returns></returns>
    public async Task<string> CheckNetwork(bool UseVpn)
    {
        string Mirror_Url = "https://mirrors.zju.edu.cn/api/is_campus_network";
        string target_uri = UseVpn ? ConvertUrl(Mirror_Url) : Mirror_Url;
        try
        {
            var response = await client.GetAsync(Mirror_Url);
            if (response.IsSuccessStatusCode)
            {
                string res_text = await response.Content.ReadAsStringAsync();
                if (res_text == "0")
                {
                    return "0";
                }
                else if (res_text == "1" || res_text == "2")
                {
                    return "1";
                }
                else
                {
                    return "404:非法返回";
                }
            }
            else
            {
                return "404:请求失败";
            }
        }
        catch (Exception ex)
        {
            return $"404:{ex.Message}";
        }


    }
    public static bool ParseLoginResult(string json)
    {
        if (string.IsNullOrEmpty(json)) return false;
        var dic = JsonConvert.DeserializeObject<Dictionary<string, object>>(json);
        if (dic == null) return false;
        if(dic.TryGetValue("success",out var r))
        {
            if(r is bool _r)
            {
                return _r;
            }
        }
        return false;
    }
    public static (string csrf,string captcha,string auth_type) GetRandCode(string html)
    {
        var doc = new HtmlDocument();
        doc.LoadHtml(html);
        var csrf_node = doc.DocumentNode.SelectSingleNode("//input[@type='hidden' and @name='_csrf']");
        var captcha_node= doc.DocumentNode.SelectSingleNode("//input[@type='hidden' and @name='captcha_id']");
        var auth_type_node= doc.DocumentNode.SelectSingleNode("//input[@type='hidden' and @name='auth_type']");
        string csrf =csrf_node?.GetAttributeValue("value", string.Empty) ?? string.Empty;
        string captcha=captcha_node?.GetAttributeValue("value", string.Empty) ?? string.Empty;
        string auth_type=auth_type_node?.GetAttributeValue("value", string.Empty) ?? string.Empty;
        return (csrf,captcha,auth_type);
    }
    /// <summary>
    /// 拼接密钥。需要指明截取长度，并默认IV,Key和前缀一致。
    /// </summary>
    /// <param name="Prefix"></param>
    /// <param name="PlainText"></param>
    /// <returns></returns>
    public static string BuildPassword(string Prefix,string PlainText,int SliceLength)
    {
        string prifix_hex=StringToAscll(Prefix);
        string full_core = EncryptStringToHex(PlainText, Prefix, Prefix);
        string core = full_core[..Math.Min(full_core.Length, SliceLength)];
        return $"{prifix_hex}{core}";
    }
    /// <summary>
    /// 核心加密实现。
    /// </summary>
    /// <param name="PlainText"></param>
    /// <param name="Key"></param>
    /// <param name="IV"></param>
    /// <returns></returns>
    public static string EncryptStringToHex(string PlainText, string Key, string IV)
    {
        byte[] iv = Encoding.UTF8.GetBytes(IV.PadRight(16, ' ')[..16]);
        byte[] key = Encoding.UTF8.GetBytes(Key.PadRight(16, ' ')[..16]);
        using (Aes aes = Aes.Create())
        {
            aes.Key = key;
            aes.IV = iv;
            aes.Mode = CipherMode.CFB;   // CFB 模式
            aes.Padding = PaddingMode.PKCS7; // 允许任意长度明文
            aes.FeedbackSize = 128;
            using (ICryptoTransform encryptor = aes.CreateEncryptor())
            using (MemoryStream ms = new MemoryStream())
            using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
            {
                byte[] plainBytes = Encoding.UTF8.GetBytes(PlainText);
                cs.Write(plainBytes, 0, plainBytes.Length);
                cs.FlushFinalBlock();
                return Convert.ToHexString(ms.ToArray()).ToLower();
            }
        }
    }
    /// <summary>
    /// 将字符串分别转化为ACSLL码。
    /// </summary>
    /// <param name="Origin"></param>
    /// <returns></returns>
    public static string StringToAscll(string Origin)
    {

        byte[] asciiBytes = Encoding.ASCII.GetBytes(Origin);
        var sb = new StringBuilder(asciiBytes.Length * 2);
        foreach (byte b in asciiBytes)
        {
            sb.Append(b.ToString("x2"));   
        }
        return sb.ToString();
    }
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }
    protected virtual void Dispose(bool disposing)
    {
        if (!_disposed)
        {
            if (disposing)
            {
                client?.Dispose();
            }
            _disposed = true;
        }
    }
}

