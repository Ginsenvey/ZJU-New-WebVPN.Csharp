### ZJU-New-WebVPN.Csharp

此脚本由Ginsenvey完成，实现以下功能：

- 登录浙江大学新版web vpn,与旧版VPN接口兼容;

- 提供链接转写方法`ConvertUrl(string url)`.url必须具备scheme,比如http/https。

- 公开了属性`IsVpnEnabled`;`client`;`Logined`;`Ticket`;`AutoDirect`,Ticket是鉴权的必要Cookie.当没有登录成功时，Ticket返回空Cookie对象。

- 重写了Http请求的发送方法，比如Send/Get/Post/Put/Delete/GetBytesArray.当`IsVpnEnabled`为true且Logined为true时，请求均使用web vpn发送，同时自动改写Url。如果Logined为False,则报错弹出。登录失败返回“400：{错误信息}”。

- 对于特殊的协议，此脚本可能不适用，需要手动修改一部分源码。
**使用样例**

```csharp
var vpn=new VpnService();
string re=await vpn.LoginAsync("your_id","your_password");
if(re=="1")
{
    //在成功登录的情况下，才能安全地设置为true
    vpn.IsVpnEnabled=true;
    //发送请求
    var res=await vpn.GetAsync("https://www.cc98.org");
}

```

