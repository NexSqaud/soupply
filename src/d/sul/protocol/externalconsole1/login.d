/*
 * This file has been automatically generated by sel-utils and
 * released under the GNU General Public License version 3.
 *
 * License: https://github.com/sel-project/sel-utils/blob/master/LICENSE
 * Repository: https://github.com/sel-project/sel-utils
 * Generator: https://github.com/sel-project/sel-utils/blob/master/xml/protocol/externalconsole1.xml
 */
module sul.protocol.externalconsole1.login;

import std.bitmanip : write, read;
import std.conv : to;
import std.system : Endian;
import std.typetuple : TypeTuple;
import std.uuid : UUID;

import sul.utils.var;

import types = sul.protocol.externalconsole1.types;

alias Packets = TypeTuple!(AuthCredentials, Auth, Welcome);

/**
 * Credentials for login.
 */
struct AuthCredentials {

	public enum ubyte ID = 0;

	public enum bool CLIENTBOUND = true;
	public enum bool SERVERBOUND = false;

	/**
	 * Protocol used by the server. If the client uses a different one it should close
	 * the connection without sending any packet.
	 */
	public ubyte protocol;

	/**
	 * Algorithm used by the server to match the the hash. If empty no hashing is done
	 * and the password is sent raw.
	 */
	public string hashAlgorithm;

	/**
	 * Payload to add to the password encoded as UTF-8 (if hash algorithm is not empty)
	 * before hashing it.
	 */
	public ubyte[16] payload;

	public ubyte[] encode(bool writeId=true)() {
		ubyte[] buffer;
		static if(writeId){ buffer~=ID; }
		buffer~=protocol;
		ubyte[] aGFzaEFsZ29yaXRo=cast(ubyte[])hashAlgorithm; buffer.length+=ushort.sizeof; write!(ushort, Endian.bigEndian)(buffer, aGFzaEFsZ29yaXRo.length.to!ushort, buffer.length-ushort.sizeof);buffer~=aGFzaEFsZ29yaXRo;
		buffer~=payload;
		return buffer;
	}

	public typeof(this) decode(bool readId=true)(ubyte[] buffer) {
		static if(readId){ typeof(ID) _id; if(buffer.length>=ubyte.sizeof){ _id=read!(ubyte, Endian.bigEndian)(buffer); } }
		if(buffer.length>=ubyte.sizeof){ protocol=read!(ubyte, Endian.bigEndian)(buffer); }
		ubyte[] aGFzaEFsZ29yaXRo; if(buffer.length>=ushort.sizeof){ aGFzaEFsZ29yaXRo.length=read!(ushort, Endian.bigEndian)(buffer); }if(buffer.length>=aGFzaEFsZ29yaXRo.length){ aGFzaEFsZ29yaXRo=buffer[0..aGFzaEFsZ29yaXRo.length]; buffer=buffer[aGFzaEFsZ29yaXRo.length..$]; }; hashAlgorithm=cast(string)aGFzaEFsZ29yaXRo;
		if(buffer.length>=payload.length){ payload=buffer[0..payload.length]; buffer=buffer[payload.length..$]; }
		return this;
	}

}

struct Auth {

	public enum ubyte ID = 1;

	public enum bool CLIENTBOUND = false;
	public enum bool SERVERBOUND = true;

	public ubyte[] hash;

	public ubyte[] encode(bool writeId=true)() {
		ubyte[] buffer;
		static if(writeId){ buffer~=ID; }
		buffer.length+=ushort.sizeof; write!(ushort, Endian.bigEndian)(buffer, hash.length.to!ushort, buffer.length-ushort.sizeof);buffer~=hash;
		return buffer;
	}

	public typeof(this) decode(bool readId=true)(ubyte[] buffer) {
		static if(readId){ typeof(ID) _id; if(buffer.length>=ubyte.sizeof){ _id=read!(ubyte, Endian.bigEndian)(buffer); } }
		if(buffer.length>=ushort.sizeof){ hash.length=read!(ushort, Endian.bigEndian)(buffer); }if(buffer.length>=hash.length){ hash=buffer[0..hash.length]; buffer=buffer[hash.length..$]; }
		return this;
	}

}

struct Welcome {

	public enum ubyte ID = 2;

	public enum bool CLIENTBOUND = true;
	public enum bool SERVERBOUND = false;

	public ubyte status;

	public ubyte[] encode(bool writeId=true)() {
		ubyte[] buffer;
		static if(writeId){ buffer~=ID; }
		buffer~=status;
		return buffer;
	}

	public typeof(this) decode(bool readId=true)(ubyte[] buffer) {
		static if(readId){ typeof(ID) _id; if(buffer.length>=ubyte.sizeof){ _id=read!(ubyte, Endian.bigEndian)(buffer); } }
		if(buffer.length>=ubyte.sizeof){ status=read!(ubyte, Endian.bigEndian)(buffer); }
		return this;
	}

}
