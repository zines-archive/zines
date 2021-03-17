/* UnTeamSpeak
 * by [g00n]JaGx (g00ns.net)
 */

using System;
using System.Collections;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;

namespace UnTeamSpeak
{
    class TeamSpeak
    {
        public Socket socket;
        public uint challenge, player_id, counter, server_version;
        public string server_name, ip, server_platform, welcome_msg, host;
        public int port;
        public IList channels, players;
        public bool logged_in;
        public Thread handler_thread;

        public TeamSpeak(string host, int port)
        {
            ip = host + ":" + port;
            this.host = host;
            this.port = port;
        }

        public void login(string agent, string os, ulong version, bool autonick, bool registered, string user, string password, string nick)
        {
            logout();
            socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            socket.Connect(host, port);
            counter = 2;
            byte[] packet = new byte[180];
            MemoryStream stream = new MemoryStream(packet);
            BinaryWriter writer = new BinaryWriter(stream);
            writer.Write(new byte[]{
             0xF4, 0xBE, 0x03
            });
            stream.Seek(20, SeekOrigin.Begin);
            writer.Write((byte)agent.Length);
            writer.Write(agent.ToCharArray());
            stream.Seek(50, SeekOrigin.Begin);
            writer.Write((byte)os.Length);
            writer.Write(os.ToCharArray());
            stream.Seek(80, SeekOrigin.Begin);
            writer.Write(version);
            writer.Write(autonick);
            writer.Write((byte)(registered ? 2 : 1));
            writer.Write((byte)user.Length);
            writer.Write(user.ToCharArray());
            stream.Seek(120, SeekOrigin.Begin);
            writer.Write((byte)password.Length);
            writer.Write(password.ToCharArray());
            stream.Seek(150, SeekOrigin.Begin);
            writer.Write((byte)nick.Length);
            writer.Write(nick.ToCharArray());
            stream.Seek(16, SeekOrigin.Begin);
            writer.Write(Crc.get(packet));
            socket.Send(packet);
            packet = new byte[436];
            socket.Receive(packet);
            stream = new MemoryStream(packet);
            BinaryReader reader = new BinaryReader(stream);
            stream.Seek(8, SeekOrigin.Begin);
            player_id = reader.ReadUInt32();
            stream.Seek(20, SeekOrigin.Begin);
            server_name = reader.ReadString();
            stream.Seek(50, SeekOrigin.Begin);
            server_platform = reader.ReadString();
            stream.Seek(80, SeekOrigin.Begin);
            server_version = reader.ReadUInt32();
            stream.Seek(172, SeekOrigin.Begin);
            challenge = reader.ReadUInt32();
            stream.Seek(180, SeekOrigin.Begin);
            welcome_msg = reader.ReadString();
            packet = new byte[120];
            stream = new MemoryStream(packet);
            writer = new BinaryWriter(stream);
            writer.Write(new byte[]{
             0xF0, 0xBE, 0x05, 0x00
            });
            writer.Write(challenge);
            writer.Write(player_id);
            writer.Write((byte)0x01);
            stream.Seek(20, SeekOrigin.Begin);
            writer.Write(Crc.get(packet));
            socket.Send(packet);
            socket.Receive(new byte[1024]);
            parseChannelsAndUsers();
            logged_in = true;
            handler_thread = new Thread(new ThreadStart(handler));
            handler_thread.Start();
        }

        void parseChannelsAndUsers()
        {
            channels = new ArrayList();
            uint id, sub_id;
            string name, topic, description;
            bool registered, moderated, has_password, subs, is_default;
            ushort codec, max_users, sort_order, properties;
            char peek;
            players = new ArrayList();
            string nick;
            byte[] packet;
            int length;
            MemoryStream stream;
            BinaryReader reader;
            byte[] ping_packet;
            MemoryStream ping_stream;
            BinaryWriter ping_writer;
            for (; ; )
            {
                packet = new byte[560];
                length = socket.Receive(packet);
                stream = new MemoryStream(packet);
                reader = new BinaryReader(stream);
                ping_packet = new byte[16];
                ping_stream = new MemoryStream(ping_packet);
                ping_writer = new BinaryWriter(ping_stream);
                ping_writer.Write(new byte[]{
                 0xF1, 0xBE, 0x00, 0x00
                });
                ping_writer.Write(challenge);
                ping_writer.Write(player_id);
                stream.Seek(12, SeekOrigin.Begin);
                ping_writer.Write(reader.ReadUInt32());
                socket.Send(ping_packet);
                stream.Seek(0, SeekOrigin.Begin);
                switch (reader.ReadUInt32())
                {
                    case 0x0006BEF0: ;
                        stream.Seek(28, SeekOrigin.Begin);
                        while (stream.Position != length)
                        {
                            id = reader.ReadUInt32();
                            properties = reader.ReadUInt16();
                            if ((properties - 16) >= 0)
                            {
                                is_default = true;
                                properties -= 16;
                            }
                            else
                            {
                                is_default = false;
                            }
                            if ((properties - 8) >= 0)
                            {
                                subs = true;
                                properties -= 8;
                            }
                            else
                            {
                                subs = false;
                            }
                            if ((properties - 4) >= 0)
                            {
                                has_password = true;
                                properties -= 4;
                            }
                            else
                            {
                                has_password = false;
                            }
                            if ((properties - 2) >= 0)
                            {
                                moderated = true;
                                properties -= 2;
                            }
                            else
                            {
                                moderated = false;
                            }
                            registered = properties == 0;
                            codec = reader.ReadUInt16();
                            sub_id = reader.ReadUInt32();
                            sort_order = reader.ReadUInt16();
                            max_users = reader.ReadUInt16();
                            name = "";
                            for (; ; )
                            {
                                try
                                {
                                    peek = reader.ReadChar();
                                }
                                catch
                                {
                                    packet = new byte[560];
                                    length = socket.Receive(packet);
                                    stream = new MemoryStream(packet);
                                    reader = new BinaryReader(stream);
                                    ping_packet = new byte[16];
                                    ping_stream = new MemoryStream(ping_packet);
                                    ping_writer = new BinaryWriter(ping_stream);
                                    ping_writer.Write(new byte[]{
                                     0xF1, 0xBE, 0x00, 0x00
                                    });
                                    ping_writer.Write(challenge);
                                    ping_writer.Write(player_id);
                                    stream.Seek(12, SeekOrigin.Begin);
                                    ping_writer.Write(reader.ReadUInt32());
                                    socket.Send(ping_packet);
                                    stream.Seek(24, SeekOrigin.Begin);
                                    peek = reader.ReadChar();
                                }
                                if (peek != 0x00)
                                {
                                    name += peek;
                                }
                                else
                                {
                                    break;
                                }
                            }
                            topic = "";
                            for (; ; )
                            {
                                try
                                {
                                    peek = reader.ReadChar();
                                }
                                catch
                                {
                                    packet = new byte[560];
                                    length = socket.Receive(packet);
                                    stream = new MemoryStream(packet);
                                    reader = new BinaryReader(stream);
                                    ping_packet = new byte[16];
                                    ping_stream = new MemoryStream(ping_packet);
                                    ping_writer = new BinaryWriter(ping_stream);
                                    ping_writer.Write(new byte[]{
                                     0xF1, 0xBE, 0x00, 0x00
                                    });
                                    ping_writer.Write(challenge);
                                    ping_writer.Write(player_id);
                                    stream.Seek(12, SeekOrigin.Begin);
                                    ping_writer.Write(reader.ReadUInt32());
                                    socket.Send(ping_packet);
                                    stream.Seek(24, SeekOrigin.Begin);
                                    peek = reader.ReadChar();
                                }
                                if (peek != 0x00)
                                {
                                    topic += peek;
                                }
                                else
                                {
                                    break;
                                }
                            }
                            description = "";
                            for (; ; )
                            {
                                try
                                {
                                    peek = reader.ReadChar();
                                }
                                catch
                                {
                                    packet = new byte[560];
                                    length = socket.Receive(packet);
                                    stream = new MemoryStream(packet);
                                    reader = new BinaryReader(stream);
                                    ping_packet = new byte[16];
                                    ping_stream = new MemoryStream(ping_packet);
                                    ping_writer = new BinaryWriter(ping_stream);
                                    ping_writer.Write(new byte[]{
                                     0xF1, 0xBE, 0x00, 0x00
                                    });
                                    ping_writer.Write(challenge);
                                    ping_writer.Write(player_id);
                                    stream.Seek(12, SeekOrigin.Begin);
                                    ping_writer.Write(reader.ReadUInt32());
                                    socket.Send(ping_packet);
                                    stream.Seek(24, SeekOrigin.Begin);
                                    peek = reader.ReadChar();
                                }
                                if (peek != 0x00)
                                {
                                    description += peek;
                                }
                                else
                                {
                                    break;
                                }
                            }
                            channels.Add(new Channel(id, sub_id, name, topic, codec, description, max_users, sort_order, registered, moderated, has_password, subs, is_default));
                        }
                        break;

                    case 0x0007BEF0:
                        stream.Seek(28, SeekOrigin.Begin);
                        while (stream.Position != length)
                        {
                            id = reader.ReadUInt32();
                            if (id == 0x00000000)
                            {
                                break;
                            }
                            stream.Seek(10, SeekOrigin.Current);
                            int next_pos = 29 - reader.PeekChar();
                            nick = reader.ReadString();
                            players.Add(new Player(id, nick));
                            stream.Seek(next_pos, SeekOrigin.Current);
                        }
                        break;

                    case 0x0008BEF0:
                        return;
                }
            }
        }

        public void logout()
        {
            if (logged_in)
            {
                byte[] packet = new byte[24];
                MemoryStream stream = new MemoryStream(packet);
                BinaryWriter writer = new BinaryWriter(stream);
                writer.Write(new byte[]{
                 0xF0, 0xBE, 0x2C, 0x01
                });
                writer.Write(challenge);
                writer.Write(player_id);
                writer.Write(counter);
                stream.Seek(20, SeekOrigin.Begin);
                writer.Write(Crc.get(packet));
                socket.Send(packet);
                handler_thread.Abort();
                handler_thread = null;
                socket.Close();
                socket = null;
                logged_in = false;
            }
        }

        private void handler()
        {
            byte[] packet = new byte[20];
            MemoryStream stream = new MemoryStream(packet);
            BinaryWriter writer = new BinaryWriter(stream);
            writer.Write(new byte[]{
             0xF4, 0xBE, 0x01, 0x00
            });
            writer.Write(challenge);
            writer.Write(player_id);
            writer.Write(Crc.get(packet));
            socket.Send(packet);
            for (; ; )
            {
                packet = new byte[560];
                socket.Receive(packet);
                stream = new MemoryStream(packet);
                BinaryReader reader = new BinaryReader(stream);
                uint command = reader.ReadUInt32();
                if (command == 0x0064BEF0)
                {
                    stream.Seek(24, SeekOrigin.Begin);
                    uint id = reader.ReadUInt32();
                    stream.Seek(38, SeekOrigin.Begin);
                    string nick = reader.ReadString();
                    stream.Seek(12, SeekOrigin.Begin);
                    uint counter = reader.ReadUInt32();
                    packet = new byte[16];
                    stream = new MemoryStream(packet);
                    writer = new BinaryWriter(stream);
                    writer.Write(new byte[]{
                     0xF1, 0xBE, 0x00, 0x00
                    });
                    writer.Write(challenge);
                    writer.Write(player_id);
                    writer.Write(counter);
                    socket.Send(packet);
                    if (nick.ToLower().Contains("static"))
                    {
                        kickPlayer(id, "KEEBLA ELF NIGGGA!");
                    }
                }
                else if (command == 0x0002BEF4)
                {
                    stream.Seek(12, SeekOrigin.Begin);
                    counter = reader.ReadUInt32();
                    /* packet = new byte[20];
                     stream = new MemoryStream(packet);
                     writer = new BinaryWriter(stream);
                     writer.Write(new byte[]{
                      0xF4, 0xBE, 0x01, 0x00
                     });
                     writer.Write(challenge);
                     writer.Write(player_id);
                     writer.Write(counter);
                     writer.Write(Crc.get(packet));*/
                    packet = new byte[16];
                    stream = new MemoryStream(packet);
                    writer = new BinaryWriter(stream);
                    writer.Write(new byte[]{
                     0xF1, 0xBE, 0x00, 0x00
                    });
                    writer.Write(challenge);
                    writer.Write(player_id);
                    writer.Write(counter);
                    socket.Send(packet);
                }
            }
        }

        public void flashLight()
        {
            byte[] packet = new byte[122];
            MemoryStream stream = new MemoryStream(packet);
            BinaryWriter writer = new BinaryWriter(stream);
            writer.Write(new byte[]{
             0xF2, 0xBE, 0x00, 0x03
            });
            writer.Write(challenge);
            writer.Write(player_id);
            writer.Write(counter++);
            stream.Seek(20, SeekOrigin.Begin);
            writer.Write(Crc.get(packet));
            socket.Send(packet);
        }

        public void grantServerAdmin(uint target_id)
        {
            byte[] packet = new byte[30];
            MemoryStream stream = new MemoryStream(packet);
            BinaryWriter writer = new BinaryWriter(stream);
            writer.Write(new byte[]{
             0xF0, 0xBE, 0x33, 0x01
            });
            writer.Write(challenge);
            writer.Write(player_id);
            writer.Write(counter++);
            stream.Seek(24, SeekOrigin.Begin);
            writer.Write(target_id);
            stream.Seek(20, SeekOrigin.Begin);
            writer.Write(Crc.get(packet));
            socket.Send(packet);
        }

        public void revokeServerAdmin(uint target_id)
        {
            byte[] packet = new byte[30];
            MemoryStream stream = new MemoryStream(packet);
            BinaryWriter writer = new BinaryWriter(stream);
            writer.Write(new byte[]{
             0xF0, 0xBE, 0x33, 0x01
            });
            writer.Write(challenge);
            writer.Write(player_id);
            writer.Write(counter++);
            stream.Seek(24, SeekOrigin.Begin);
            writer.Write(target_id);
            writer.Write((byte)0x02);
            stream.Seek(20, SeekOrigin.Begin);
            writer.Write(Crc.get(packet));
            socket.Send(packet);
        }

        public void grantChannelAdmin(uint target_id)
        {
            byte[] packet = new byte[30];
            MemoryStream stream = new MemoryStream(packet);
            BinaryWriter writer = new BinaryWriter(stream);
            writer.Write(new byte[]{
             0xF0, 0xBE, 0x32, 0x01
            });
            writer.Write(challenge);
            writer.Write(player_id);
            writer.Write(counter++);
            stream.Seek(24, SeekOrigin.Begin);
            writer.Write(target_id);
            stream.Seek(20, SeekOrigin.Begin);
            writer.Write(Crc.get(packet));
            socket.Send(packet);
        }

        public void revokeChannelAdmin(uint target_id)
        {
            byte[] packet = new byte[30];
            MemoryStream stream = new MemoryStream(packet);
            BinaryWriter writer = new BinaryWriter(stream);
            writer.Write(new byte[]{
             0xF0, 0xBE, 0x32, 0x01
            });
            writer.Write(challenge);
            writer.Write(player_id);
            writer.Write(counter++);
            stream.Seek(24, SeekOrigin.Begin);
            writer.Write(target_id);
            writer.Write((byte)0x02);
            stream.Seek(20, SeekOrigin.Begin);
            writer.Write(Crc.get(packet));
            socket.Send(packet);
        }

        public void grantVoice(uint target_id)
        {
            byte[] packet = new byte[30];
            MemoryStream stream = new MemoryStream(packet);
            BinaryWriter writer = new BinaryWriter(stream);
            writer.Write(new byte[]{
             0xF0, 0xBE, 0x32, 0x01
            });
            writer.Write(challenge);
            writer.Write(player_id);
            writer.Write(counter++);
            stream.Seek(24, SeekOrigin.Begin);
            writer.Write(target_id);
            writer.Write((ushort)0x0200);
            stream.Seek(20, SeekOrigin.Begin);
            writer.Write(Crc.get(packet));
            socket.Send(packet);
        }

        public void revokeVoice(uint target_id)
        {
            byte[] packet = new byte[30];
            MemoryStream stream = new MemoryStream(packet);
            BinaryWriter writer = new BinaryWriter(stream);
            writer.Write(new byte[]{
             0xF0, 0xBE, 0x32, 0x01
            });
            writer.Write(challenge);
            writer.Write(player_id);
            writer.Write(counter++);
            stream.Seek(24, SeekOrigin.Begin);
            writer.Write(target_id);
            writer.Write((byte)0x02);
            writer.Write((byte)0x02);
            stream.Seek(20, SeekOrigin.Begin);
            writer.Write(Crc.get(packet));
            socket.Send(packet);
        }

        public void requestVoice(string reason)
        {
            byte[] packet = new byte[54];
            MemoryStream stream = new MemoryStream(packet);
            BinaryWriter writer = new BinaryWriter(stream);
            writer.Write(new byte[]{
             0xF0, 0xBE, 0x31, 0x01
            });
            writer.Write(challenge);
            writer.Write(player_id);
            writer.Write(counter++);
            stream.Seek(24, SeekOrigin.Begin);
            writer.Write(reason);
            stream.Seek(20, SeekOrigin.Begin);
            writer.Write(Crc.get(packet));
            socket.Send(packet);
        }

        public void unRequestVoice()
        {
            byte[] packet = new byte[26];
            MemoryStream stream = new MemoryStream(packet);
            BinaryWriter writer = new BinaryWriter(stream);
            writer.Write(new byte[]{
             0xF0, 0xBE, 0x30, 0x01
            });
            writer.Write(challenge);
            writer.Write(player_id);
            writer.Write(counter++);
            stream.Seek(20, SeekOrigin.Begin);
            writer.Write(Crc.get(packet));
            socket.Send(packet);
        }

        public void kickPlayer(uint target_id, string reason)
        {
            byte[] packet = new byte[58];
            MemoryStream stream = new MemoryStream(packet);
            BinaryWriter writer = new BinaryWriter(stream);
            writer.Write(new byte[]{
             0xF0, 0xBE, 0x2D, 0x01
            });
            writer.Write(challenge);
            writer.Write(player_id);
            writer.Write(counter++);
            stream.Seek(24, SeekOrigin.Begin);
            writer.Write(target_id);
            writer.Write(reason);
            stream.Seek(20, SeekOrigin.Begin);
            writer.Write(Crc.get(packet));
            socket.Send(packet);
        }

        public void createChannel(string name, string topic, string password, ushort codec, string description, ushort max_users, ushort sort_order, bool registered, bool moderated, bool subs, bool is_default)
        {
            byte[] packet = new byte[44 + name.Length + topic.Length + password.Length + description.Length];
            MemoryStream stream = new MemoryStream(packet);
            BinaryWriter writer = new BinaryWriter(stream);
            writer.Write(new byte[]{
             0xF0, 0xBE, 0xC9, 0x00
            });
            writer.Write(challenge);
            writer.Write(player_id);
            writer.Write(counter++);
            stream.Seek(28, SeekOrigin.Begin);
            writer.Write((ushort)(1 + (registered ? -1 : 0) + (moderated ? 2 : 0) + (subs ? 8 : 0) + (is_default ? 16 : 0)));
            writer.Write(codec);
            writer.Write(new byte[]{
             0xFF, 0xFF, 0xFF, 0xFF,
            });
            writer.Write(sort_order);
            writer.Write(max_users);
            writer.Write(name.ToCharArray());
            stream.Seek(1, SeekOrigin.Current);
            writer.Write(topic.ToCharArray());
            stream.Seek(1, SeekOrigin.Current);
            writer.Write(description.ToCharArray());
            stream.Seek(1, SeekOrigin.Current);
            writer.Write(password.ToCharArray());
            stream.Seek(20, SeekOrigin.Begin);
            writer.Write(Crc.get(packet));
            socket.Send(packet);
        }

        public void createSubChannel(uint sub_id, string name, string topic, string description, ushort max_users, ushort sort_order)
        {
            byte[] packet = new byte[44 + name.Length + topic.Length + description.Length];
            MemoryStream stream = new MemoryStream(packet);
            BinaryWriter writer = new BinaryWriter(stream);
            writer.Write(new byte[]{
             0xF0, 0xBE, 0xC9, 0x00
            });
            writer.Write(challenge);
            writer.Write(player_id);
            writer.Write(counter++);
            stream.Seek(32, SeekOrigin.Begin);
            writer.Write(sub_id);
            writer.Write(sort_order);
            writer.Write(max_users);
            writer.Write(name.ToCharArray());
            stream.Seek(1, SeekOrigin.Current);
            writer.Write(topic.ToCharArray());
            stream.Seek(1, SeekOrigin.Current);
            writer.Write(description.ToCharArray());
            stream.Seek(20, SeekOrigin.Begin);
            writer.Write(Crc.get(packet));
            socket.Send(packet);
        }

        public void joinChannel(uint channel_id)
        {
            byte[] packet = new byte[58];
            MemoryStream stream = new MemoryStream(packet);
            BinaryWriter writer = new BinaryWriter(stream);
            writer.Write(new byte[]{
             0xF0, 0xBE, 0x2F, 0x01
            });
            writer.Write(challenge);
            writer.Write(player_id);
            writer.Write(counter++);
            stream.Seek(24, SeekOrigin.Begin);
            writer.Write(channel_id);
            stream.Seek(20, SeekOrigin.Begin);
            writer.Write(Crc.get(packet));
            socket.Send(packet);
        }

        public void deleteChannel(uint channel_id)
        {
            byte[] packet = new byte[28];
            MemoryStream stream = new MemoryStream(packet);
            BinaryWriter writer = new BinaryWriter(stream);
            writer.Write(new byte[]{
             0xF0, 0xBE, 0xD1, 0x00
            });
            writer.Write(challenge);
            writer.Write(player_id);
            writer.Write(counter++);
            stream.Seek(24, SeekOrigin.Begin);
            writer.Write(channel_id);
            stream.Seek(20, SeekOrigin.Begin);
            writer.Write(Crc.get(packet));
            socket.Send(packet);
        }

        public void sendMessageToAll(string message)
        {
            int length = 36 + message.Length;
            byte[] packet = new byte[length];
            MemoryStream stream = new MemoryStream(packet);
            BinaryWriter writer = new BinaryWriter(stream);
            writer.Write(new byte[]{
             0xF0, 0xBE, 0xAE, 0x01
            });
            writer.Write(challenge);
            writer.Write(player_id);
            writer.Write(counter++);
            stream.Seek(33, SeekOrigin.Begin);
            writer.Write(message.ToCharArray());
            stream.Seek(20, SeekOrigin.Begin);
            writer.Write(Crc.get(packet));
            socket.Send(packet);
        }
        public void sendMessageToChannel(uint channel_id, string message)
        {
            int length = 36 + message.Length;
            byte[] packet = new byte[length];
            MemoryStream stream = new MemoryStream(packet);
            BinaryWriter writer = new BinaryWriter(stream);
            writer.Write(new byte[]{
             0xF0, 0xBE, 0xAE, 0x01
            });
            writer.Write(challenge);
            writer.Write(player_id);
            writer.Write(counter++);
            stream.Seek(28, SeekOrigin.Begin);
            writer.Write((byte)0x01);
            writer.Write(channel_id);
            stream.Seek(33, SeekOrigin.Begin);
            writer.Write(message.ToCharArray());
            stream.Seek(20, SeekOrigin.Begin);
            writer.Write(Crc.get(packet));
            socket.Send(packet);
        }

        public void sendMessageToPlayer(uint recipient_id, string message)
        {
            int length = 36 + message.Length;
            byte[] packet = new byte[length];
            MemoryStream stream = new MemoryStream(packet);
            BinaryWriter writer = new BinaryWriter(stream);
            writer.Write(new byte[]{
             0xF0, 0xBE, 0xAE, 0x01
            });
            writer.Write(challenge);
            writer.Write(player_id);
            writer.Write(counter++);
            stream.Seek(28, SeekOrigin.Begin);
            writer.Write((byte)0x02);
            writer.Write(recipient_id);
            stream.Seek(33, SeekOrigin.Begin);
            writer.Write(message.ToCharArray());
            stream.Seek(20, SeekOrigin.Begin);
            writer.Write(Crc.get(packet));
            socket.Send(packet);
        }

        public Player getPlayerByNick(string nick)
        {
            IEnumerator enumerator = players.GetEnumerator();
            while (enumerator.MoveNext())
            {
                if (((Player)enumerator.Current).nick == nick)
                {
                    return (Player)enumerator.Current;
                }
            }
            return null;
        }
    }
}
