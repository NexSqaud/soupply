/*
 * This file has been automatically generated by sel-utils and
 * released under the GNU General Public License version 3.
 *
 * License: https://github.com/sel-project/sel-utils/blob/master/LICENSE
 * Repository: https://github.com/sel-project/sel-utils
 * Generator: https://github.com/sel-project/sel-utils/blob/master/xml/protocol/minecraft316.xml
 */
module sul.protocol.minecraft316.status;

import std.bitmanip : write, read;
import std.conv : to;
import std.system : Endian;
import std.typetuple : TypeTuple;
import std.uuid : UUID;

import sul.utils.var;

import types = sul.protocol.minecraft316.types;

alias Packets = TypeTuple!(Handshake, Request, Response, Ping, Pong);

struct Handshake {

	public enum uint ID = 0;

	public enum bool CLIENTBOUND = false;
	public enum bool SERVERBOUND = true;

	// next
	public enum uint STATUS = 1;
	public enum uint LOGIN = 2;

	public uint protocol;
	public string serverAddress;
	public ushort serverPort;
	public uint next;

	public ubyte[] encode(bool writeId=true)() {
		ubyte[] buffer;
		static if(writeId){ buffer~=varuint.encode(ID); }
		buffer~=varuint.encode(protocol);
		ubyte[] c2VydmVyQWRkcmVz=cast(ubyte[])serverAddress; buffer~=varuint.encode(c2VydmVyQWRkcmVz.length.to!uint);buffer~=c2VydmVyQWRkcmVz;
		buffer.length+=ushort.sizeof; write!(ushort, Endian.bigEndian)(buffer, serverPort, buffer.length-ushort.sizeof);
		buffer~=varuint.encode(next);
		return buffer;
	}

	public typeof(this) decode(bool readId=true)(ubyte[] buffer) {
		static if(readId){ typeof(ID) _id; _id=varuint.decode(buffer); }
		protocol=varuint.decode(buffer);
		ubyte[] c2VydmVyQWRkcmVz; c2VydmVyQWRkcmVz.length=varuint.decode(buffer);if(buffer.length>=c2VydmVyQWRkcmVz.length){ c2VydmVyQWRkcmVz=buffer[0..c2VydmVyQWRkcmVz.length]; buffer=buffer[c2VydmVyQWRkcmVz.length..$]; }; serverAddress=cast(string)c2VydmVyQWRkcmVz;
		if(buffer.length>=ushort.sizeof){ serverPort=read!(ushort, Endian.bigEndian)(buffer); }
		next=varuint.decode(buffer);
		return this;
	}

}

struct Request {

	public enum uint ID = 0;

	public enum bool CLIENTBOUND = false;
	public enum bool SERVERBOUND = true;

	public ubyte[] encode(bool writeId=true)() {
		ubyte[] buffer;
		static if(writeId){ buffer~=varuint.encode(ID); }
		return buffer;
	}

	public typeof(this) decode(bool readId=true)(ubyte[] buffer) {
		static if(readId){ typeof(ID) _id; _id=varuint.decode(buffer); }
		return this;
	}

}

struct Response {

	public enum uint ID = 0;

	public enum bool CLIENTBOUND = true;
	public enum bool SERVERBOUND = false;

	public string json;

	public ubyte[] encode(bool writeId=true)() {
		ubyte[] buffer;
		static if(writeId){ buffer~=varuint.encode(ID); }
		ubyte[] anNvbg=cast(ubyte[])json; buffer~=varuint.encode(anNvbg.length.to!uint);buffer~=anNvbg;
		return buffer;
	}

	public typeof(this) decode(bool readId=true)(ubyte[] buffer) {
		static if(readId){ typeof(ID) _id; _id=varuint.decode(buffer); }
		ubyte[] anNvbg; anNvbg.length=varuint.decode(buffer);if(buffer.length>=anNvbg.length){ anNvbg=buffer[0..anNvbg.length]; buffer=buffer[anNvbg.length..$]; }; json=cast(string)anNvbg;
		return this;
	}

}

struct Ping {

	public enum uint ID = 1;

	public enum bool CLIENTBOUND = false;
	public enum bool SERVERBOUND = true;

	public long pingId;

	public ubyte[] encode(bool writeId=true)() {
		ubyte[] buffer;
		static if(writeId){ buffer~=varuint.encode(ID); }
		buffer.length+=long.sizeof; write!(long, Endian.bigEndian)(buffer, pingId, buffer.length-long.sizeof);
		return buffer;
	}

	public typeof(this) decode(bool readId=true)(ubyte[] buffer) {
		static if(readId){ typeof(ID) _id; _id=varuint.decode(buffer); }
		if(buffer.length>=long.sizeof){ pingId=read!(long, Endian.bigEndian)(buffer); }
		return this;
	}

}

struct Pong {

	public enum uint ID = 1;

	public enum bool CLIENTBOUND = true;
	public enum bool SERVERBOUND = false;

	public long pingId;

	public ubyte[] encode(bool writeId=true)() {
		ubyte[] buffer;
		static if(writeId){ buffer~=varuint.encode(ID); }
		buffer.length+=long.sizeof; write!(long, Endian.bigEndian)(buffer, pingId, buffer.length-long.sizeof);
		return buffer;
	}

	public typeof(this) decode(bool readId=true)(ubyte[] buffer) {
		static if(readId){ typeof(ID) _id; _id=varuint.decode(buffer); }
		if(buffer.length>=long.sizeof){ pingId=read!(long, Endian.bigEndian)(buffer); }
		return this;
	}

}
