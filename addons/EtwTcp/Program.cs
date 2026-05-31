using System;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;
using System.Text;
using System.Net;
using System.Net.Sockets;

class NetCapture
{
    static long packetCounter = 0;

    static void Main()
    {
        if (!TraceEventSession.IsElevated()?? false)
        {
            Console.WriteLine("Error: administration privileges are needed.");
            return;
        }

        // Создаем именованный канал для передачи данных в Python
        using var pipeServer = new NamedPipeServerStream("NetMonitorPipe", PipeDirection.Out);
        Console.WriteLine("Waiting for python-script connecting...");
        pipeServer.WaitForConnection();
        using var writer = new StreamWriter(pipeServer, Encoding.UTF8) { AutoFlush = true };

        using var session = new TraceEventSession("NetMonSession");
        session.EnableKernelProvider(KernelTraceEventParser.Keywords.NetworkTCPIP);

        var kernel = session.Source.Kernel;

        // Обработка событий
        kernel.TcpIpSend += e => SendToPipe(writer, e, "TCP", "OUT");
        kernel.TcpIpRecv += e => SendToPipe(writer, e, "TCP", "IN");
        kernel.UdpIpSend += e => SendToPipe(writer, e, "UDP", "OUT");
        kernel.UdpIpRecv += e => SendToPipe(writer, e, "UDP", "IN");

        kernel.TcpIpSendIPV6 += e => SendToPipe(writer, e, "TCP", "OUT");
        kernel.TcpIpRecvIPV6 += e => SendToPipe(writer, e, "TCP", "IN");
        kernel.UdpIpSendIPV6 += e => SendToPipe(writer, e, "UDP", "OUT");
        kernel.UdpIpRecvIPV6 += e => SendToPipe(writer, e, "UDP", "IN");

        Console.WriteLine("Monitor is running. Data is passing to python...");
        session.Source.Process();
    }

    static void SendToPipe(StreamWriter writer, dynamic e, string proto, string dir)
    {
        string srcIp = e.saddr?.ToString();
        string dstIp = e.daddr?.ToString();

        packetCounter++;

        string procName;
        try { procName = Process.GetProcessById(e.ProcessID).ProcessName; }
        catch { procName = "ExitedProcess"; }

        var sizeVal = e.size ?? 0;

        long tsMicros;
        try
        {
            DateTime dt = e.TimeStamp;
            var dto = new DateTimeOffset(dt.ToUniversalTime());
            long ms = dto.ToUnixTimeMilliseconds();
            long remTicks = dt.Ticks % TimeSpan.TicksPerMillisecond;
            long remMicros = remTicks / 10;
            tsMicros = ms * 1000 + remMicros;
        }
        catch
        {
            var now = DateTimeOffset.UtcNow;
            tsMicros = now.ToUnixTimeMilliseconds() * 1000;
        }

        // Формирование и передача данных
        string data =
            $"{packetCounter}|{e.ProcessID}|{procName}|{proto}|{dir}|" +
            $"{srcIp}|{e.sport}|{dstIp}|{e.dport}|{sizeVal}|{tsMicros}";

        try
        {
            writer.WriteLine(data);
        }
        catch
        {
            Environment.Exit(0);
        }
    }
}