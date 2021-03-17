using System;
using System.Collections.Generic;
using System.Text;

namespace UnTeamSpeak
{
    class Player
    {
        public uint id;
        public string nick;

        public Player(uint id, string nick)
        {
            this.id = id;
            this.nick = nick;
        }

        public override string ToString()
        {
            return id + ": " + nick;
        }
    }
}
