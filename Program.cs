using System.Net;
using System.Net.Sockets;
using System.Text;

byte[] _5011 = { 5, 0, 1, 1 };
byte[] PublicIP = { 127, 0, 0, 1 };
byte[] LocalIP = { 0, 0, 0, 0 };
var LocalPort = 8888;

async Task ForwardData(Stream input, Stream output)
{
    try
    {
        await input.CopyToAsync(output);
    }
    catch (Exception ex)
    {
        Console.WriteLine("数据转发出错：" + ex.Message);
    }
}

async Task HandleClient(TcpClient client)
{
    try
    {
        var targetClient = new TcpClient();
        var clientStream = client.GetStream();
        // methods packet
        var packetVersion = clientStream.ReadByte();
        if (packetVersion != 5) throw new NotSupportedException($"ERROR: not Socks5 packet {packetVersion}");
        clientStream.WriteByte(5);
        var nMethods = clientStream.ReadByte();
        var methods = new byte[nMethods];
        clientStream.Read(methods, 0, nMethods);
        var clientSupportNoAuth = false;
        for (var i = 0; i < nMethods; ++i)
            if (methods[i] == 0)
            {
                clientSupportNoAuth = true;
                break;
            }

        if (!clientSupportNoAuth)
        {
            clientStream.WriteByte(0xFF);
            throw new NotSupportedException("no support auth");
        }

        clientStream.WriteByte(0);
        // command packet
        clientStream.ReadByte(); //0x05
        var clientCommand = clientStream.ReadByte();

        switch (clientCommand)
        {
            case 1: // connect
                clientStream.ReadByte(); //RSV
                var addrType = clientStream.ReadByte();
                switch (addrType)
                {
                    case 1: //ipv4
                        var addr = new byte[4];
                        _ = clientStream.Read(addr, 0, 4);
                        var remotePort = clientStream.ReadByte();
                        remotePort = remotePort * 256 + clientStream.ReadByte();
                        await targetClient.ConnectAsync(new IPAddress(addr), remotePort);
                        break;
                    case 3: //domain
                        var nDomain = clientStream.ReadByte();
                        var domain = new byte[nDomain];
                        _ = clientStream.Read(domain, 0, nDomain);
                        var remotePort3 = clientStream.ReadByte();
                        remotePort3 = remotePort3 * 256 + clientStream.ReadByte();
                        var remoteSite = Encoding.UTF8.GetString(domain);
                        Console.WriteLine($"Connect to {remoteSite}");
                        await targetClient.ConnectAsync(remoteSite, remotePort3);
                        break;
                    default: //ipv6 and more
                        throw new NotSupportedException($"not supported addr findings {addrType}");
                }

                break;
            default:
                throw new NotSupportedException($"not supported client command {clientCommand}");
        }
        // response

        clientStream.Write(_5011);
        // addr
        clientStream.Write(PublicIP);
        // port
        clientStream.WriteByte((byte)(LocalPort / 256));
        clientStream.WriteByte((byte)(LocalPort % 256));

        var targetStream = targetClient.GetStream();

        var clientToTarget = ForwardData(clientStream, targetStream);
        var targetToClient = ForwardData(targetStream, clientStream);

        await Task.WhenAll(new List<Task> { clientToTarget, targetToClient });
    }
    catch (Exception ex)
    {
        Console.WriteLine("HandleClient ERROR " + ex.Message);
    }
    finally
    {
        Console.WriteLine(
            $"<-x-> {((IPEndPoint)client.Client.RemoteEndPoint).Address}:{((IPEndPoint)client.Client.RemoteEndPoint).Port}");
        client.Close();
    }
}

var listener = new TcpListener(new IPAddress(LocalIP), LocalPort);
listener.Start();
Console.WriteLine("listen begin");
while (true)
    try
    {
        var client = await listener.AcceptTcpClientAsync();
        Console.WriteLine(
            $"<- {((IPEndPoint)client.Client.RemoteEndPoint).Address}:{((IPEndPoint)client.Client.RemoteEndPoint).Port}");
        _ = Task.Run(() => HandleClient(client));
    }
    catch (Exception ex)
    {
        Console.WriteLine("Main ERROR " + ex.Message);
    }