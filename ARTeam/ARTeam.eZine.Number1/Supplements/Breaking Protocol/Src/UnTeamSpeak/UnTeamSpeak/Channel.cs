using System;
using System.Collections.Generic;
using System.Text;

namespace UnTeamSpeak
{
    class Channel
    {
        public uint id, sub_id;
        public string name, topic, description;
        public bool registered, moderated, has_password, subs, is_default;
        public ushort codec, max_users, sort_order;

        public Channel(uint id, uint sub_id, string name, string topic, ushort codec, string description, ushort max_users, ushort sort_order, bool registered, bool moderated, bool has_password, bool subs, bool is_default)
        {
            this.id = id;
            this.sub_id = sub_id;
            this.name = name;
            this.topic = topic;
            this.codec = codec;
            this.description = description;
            this.max_users = max_users;
            this.sort_order = sort_order;
            this.registered = registered;
            this.moderated = moderated;
            this.has_password = has_password;
            this.subs = subs; 
            this.is_default = is_default;
        }

        public override string ToString()
        {
            return id + ": " + name + " (" + (registered ? "R" : "U") + (moderated ? "M" : "") + (has_password ? "P" : "") + (subs ? "S" : "") + (is_default ? "D" : "") + ")\n\rTopic:\n\r" + topic + "\n\rDescription:\n\r" + description + "\r\n";
        }
    }
}
