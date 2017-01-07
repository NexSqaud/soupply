/*
 * This file has been automatically generated by sel-utils and
 * released under the GNU General Public License version 3.
 *
 * License: https://github.com/sel-project/sel-utils/blob/master/LICENSE
 * Repository: https://github.com/sel-project/sel-utils
 * Generator: https://github.com/sel-project/sel-utils/blob/master/xml/protocol/raknet8.xml
 */
module sul.protocol.raknet8.unconnected;

import std.bitmanip : write, read;
import std.conv : to;
import std.system : Endian;
import std.typetuple : TypeTuple;
import std.uuid : UUID;

import sul.utils.var;

import types = sul.protocol.raknet8.types;

alias Packets = TypeTuple!(Ping, Pong, OpenConnectionRequest1, OpenConnectionReply1, OpenConnectionRequest2, OpenConnectionReply2);

struct Ping {

	public enum ubyte ID = 1;

	public enum bool CLIENTBOUND = false;
	public enum bool SERVERBOUND = true;

	public long pingId;
	public ubyte[16] magic;

	public ubyte[] encode(bool writeId=true)() {
		ubyte[] buffer;
		static if(writeId){ buffer~=ID; }
		buffer.length+=long.sizeof; write!(long, Endian.bigEndian)(buffer, pingId, buffer.length-long.sizeof);
		buffer~=magic;
		return buffer;
	}

	public typeof(this) decode(bool readId=true)(ubyte[] buffer) {
		static if(readId){ typeof(ID) _id; if(buffer.length>=ubyte.sizeof){ _id=read!(ubyte, Endian.bigEndian)(buffer); } }
		if(buffer.length>=long.sizeof){ pingId=read!(long, Endian.bigEndian)(buffer); }
		if(buffer.length>=magic.length){ magic=buffer[0..magic.length]; buffer=buffer[magic.length..$]; }
		return this;
	}

}

struct Pong {

	public enum ubyte ID = 28;

	public enum bool CLIENTBOUND = true;
	public enum bool SERVERBOUND = false;

	public long pingId;
	public long serverId;
	public ubyte[16] magic;
	public string status;

	public ubyte[] encode(bool writeId=true)() {
		ubyte[] buffer;
		static if(writeId){ buffer~=ID; }
		buffer.length+=long.sizeof; write!(long, Endian.bigEndian)(buffer, pingId, buffer.length-long.sizeof);
		buffer.length+=long.sizeof; write!(long, Endian.bigEndian)(buffer, serverId, buffer.length-long.sizeof);
		buffer~=magic;
		ubyte[] c3RhdHVz=cast(ubyte[])status; buffer.length+=ushort.sizeof; write!(ushort, Endian.bigEndian)(buffer, c3RhdHVz.length.to!ushort, buffer.length-ushort.sizeof);buffer~=c3RhdHVz;
		return buffer;
	}

	public typeof(this) decode(bool readId=true)(ubyte[] buffer) {
		static if(readId){ typeof(ID) _id; if(buffer.length>=ubyte.sizeof){ _id=read!(ubyte, Endian.bigEndian)(buffer); } }
		if(buffer.length>=long.sizeof){ pingId=read!(long, Endian.bigEndian)(buffer); }
		if(buffer.length>=long.sizeof){ serverId=read!(long, Endian.bigEndian)(buffer); }
		if(buffer.length>=magic.length){ magic=buffer[0..magic.length]; buffer=buffer[magic.length..$]; }
		ubyte[] c3RhdHVz; if(buffer.length>=ushort.sizeof){ c3RhdHVz.length=read!(ushort, Endian.bigEndian)(buffer); }if(buffer.length>=c3RhdHVz.length){ c3RhdHVz=buffer[0..c3RhdHVz.length]; buffer=buffer[c3RhdHVz.length..$]; }; status=cast(string)c3RhdHVz;
		return this;
	}

}

struct OpenConnectionRequest1 {

	public enum ubyte ID = 5;

	public enum bool CLIENTBOUND = false;
	public enum bool SERVERBOUND = true;

	public ubyte[16] magic;
	public ubyte protocol;
	public ubyte[] mtu;

	public ubyte[] encode(bool writeId=true)() {
		ubyte[] buffer;
		static if(writeId){ buffer~=ID; }
		buffer~=magic;
		buffer~=protocol;
		buffer~=mtu;
		return buffer;
	}

	public typeof(this) decode(bool readId=true)(ubyte[] buffer) {
		static if(readId){ typeof(ID) _id; if(buffer.length>=ubyte.sizeof){ _id=read!(ubyte, Endian.bigEndian)(buffer); } }
		if(buffer.length>=magic.length){ magic=buffer[0..magic.length]; buffer=buffer[magic.length..$]; }
		if(buffer.length>=ubyte.sizeof){ protocol=read!(ubyte, Endian.bigEndian)(buffer); }
		mtu=buffer.dup; buffer.length=0;
		return this;
	}

}

struct OpenConnectionReply1 {

	public enum ubyte ID = 6;

	public enum bool CLIENTBOUND = true;
	public enum bool SERVERBOUND = false;

	public ubyte[16] magic;
	public long serverId;
	public bool security;
	public ushort mtuLength;

	public ubyte[] encode(bool writeId=true)() {
		ubyte[] buffer;
		static if(writeId){ buffer~=ID; }
		buffer~=magic;
		buffer.length+=long.sizeof; write!(long, Endian.bigEndian)(buffer, serverId, buffer.length-long.sizeof);
		buffer.length+=bool.sizeof; write!(bool, Endian.bigEndian)(buffer, security, buffer.length-bool.sizeof);
		buffer.length+=ushort.sizeof; write!(ushort, Endian.bigEndian)(buffer, mtuLength, buffer.length-ushort.sizeof);
		return buffer;
	}

	public typeof(this) decode(bool readId=true)(ubyte[] buffer) {
		static if(readId){ typeof(ID) _id; if(buffer.length>=ubyte.sizeof){ _id=read!(ubyte, Endian.bigEndian)(buffer); } }
		if(buffer.length>=magic.length){ magic=buffer[0..magic.length]; buffer=buffer[magic.length..$]; }
		if(buffer.length>=long.sizeof){ serverId=read!(long, Endian.bigEndian)(buffer); }
		if(buffer.length>=bool.sizeof){ security=read!(bool, Endian.bigEndian)(buffer); }
		if(buffer.length>=ushort.sizeof){ mtuLength=read!(ushort, Endian.bigEndian)(buffer); }
		return this;
	}

}

struct OpenConnectionRequest2 {

	public enum ubyte ID = 7;

	public enum bool CLIENTBOUND = false;
	public enum bool SERVERBOUND = true;

	public ubyte[16] magic;
	public types.Address serverAddress;
	public ushort mtuLength;
	public long clientId;

	public ubyte[] encode(bool writeId=true)() {
		ubyte[] buffer;
		static if(writeId){ buffer~=ID; }
		buffer~=magic;
		serverAddress.encode(buffer);
		buffer.length+=ushort.sizeof; write!(ushort, Endian.bigEndian)(buffer, mtuLength, buffer.length-ushort.sizeof);
		buffer.length+=long.sizeof; write!(long, Endian.bigEndian)(buffer, clientId, buffer.length-long.sizeof);
		return buffer;
	}

	public typeof(this) decode(bool readId=true)(ubyte[] buffer) {
		static if(readId){ typeof(ID) _id; if(buffer.length>=ubyte.sizeof){ _id=read!(ubyte, Endian.bigEndian)(buffer); } }
		if(buffer.length>=magic.length){ magic=buffer[0..magic.length]; buffer=buffer[magic.length..$]; }
		serverAddress.decode(buffer);
		if(buffer.length>=ushort.sizeof){ mtuLength=read!(ushort, Endian.bigEndian)(buffer); }
		if(buffer.length>=long.sizeof){ clientId=read!(long, Endian.bigEndian)(buffer); }
		return this;
	}

}

struct OpenConnectionReply2 {

	public enum ubyte ID = 8;

	public enum bool CLIENTBOUND = true;
	public enum bool SERVERBOUND = false;

	public ubyte[16] magic;
	public long serverId;
	public types.Address serverAddress;
	public ushort mtuLength;
	public bool security;

	public ubyte[] encode(bool writeId=true)() {
		ubyte[] buffer;
		static if(writeId){ buffer~=ID; }
		buffer~=magic;
		buffer.length+=long.sizeof; write!(long, Endian.bigEndian)(buffer, serverId, buffer.length-long.sizeof);
		serverAddress.encode(buffer);
		buffer.length+=ushort.sizeof; write!(ushort, Endian.bigEndian)(buffer, mtuLength, buffer.length-ushort.sizeof);
		buffer.length+=bool.sizeof; write!(bool, Endian.bigEndian)(buffer, security, buffer.length-bool.sizeof);
		return buffer;
	}

	public typeof(this) decode(bool readId=true)(ubyte[] buffer) {
		static if(readId){ typeof(ID) _id; if(buffer.length>=ubyte.sizeof){ _id=read!(ubyte, Endian.bigEndian)(buffer); } }
		if(buffer.length>=magic.length){ magic=buffer[0..magic.length]; buffer=buffer[magic.length..$]; }
		if(buffer.length>=long.sizeof){ serverId=read!(long, Endian.bigEndian)(buffer); }
		serverAddress.decode(buffer);
		if(buffer.length>=ushort.sizeof){ mtuLength=read!(ushort, Endian.bigEndian)(buffer); }
		if(buffer.length>=bool.sizeof){ security=read!(bool, Endian.bigEndian)(buffer); }
		return this;
	}

}
