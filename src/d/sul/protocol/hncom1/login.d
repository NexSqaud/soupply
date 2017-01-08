/*
 * This file has been automatically generated by sel-utils and
 * released under the GNU General Public License version 3.
 *
 * License: https://github.com/sel-project/sel-utils/blob/master/LICENSE
 * Repository: https://github.com/sel-project/sel-utils
 * Generator: https://github.com/sel-project/sel-utils/blob/master/xml/protocol/hncom1.xml
 */
module sul.protocol.hncom1.login;

import std.bitmanip : write, peek;
import std.conv : to;
import std.system : Endian;
import std.typetuple : TypeTuple;
import std.typecons : Tuple;
import std.uuid : UUID;

import sul.utils.var;

import types = sul.protocol.hncom1.types;

alias Packets = TypeTuple!(Connection, ConnectionResponse, Info, Ready);

struct Connection {

	public enum ubyte ID = 0;

	public enum bool CLIENTBOUND = false;
	public enum bool SERVERBOUND = true;

	/**
	 * Version of the protocol used by the client that must match the hub's one
	 */
	public uint protocol;

	/**
	 * Name of the node that will be validated by the hub.
	 */
	public string name;

	/**
	 * Indicates whether the node accepts clients when they first connect to the hub or
	 * exclusively when they are manually transferred.
	 */
	public bool mainNode;

	public ubyte[] encode(bool writeId=true)() {
		ubyte[] _buffer;
		static if(writeId){ _buffer~=ID; }
		_buffer~=varuint.encode(protocol);
		ubyte[] bmFtZQ=cast(ubyte[])name; _buffer~=varuint.encode(bmFtZQ.length.to!uint);_buffer~=bmFtZQ;
		_buffer.length+=bool.sizeof; write!(bool, Endian.bigEndian)(_buffer, mainNode, _buffer.length-bool.sizeof);
		return _buffer;
	}

	public typeof(this) decode(bool readId=true)(ubyte[] _buffer, size_t _index=0) {
		return this.decode!readId(_buffer, &_index);
	}

	public typeof(this) decode(bool readId=true)(ubyte[] _buffer, size_t* _index) {
		static if(readId){ typeof(ID) _id; if(_buffer.length>=*_index+ubyte.sizeof){ _id=peek!(ubyte, Endian.bigEndian)(_buffer, _index); } }
		protocol=varuint.decode(_buffer, *_index);
		ubyte[] bmFtZQ; bmFtZQ.length=varuint.decode(_buffer, *_index);if(_buffer.length>=*_index+bmFtZQ.length){ bmFtZQ=_buffer[*_index..*_index+bmFtZQ.length].dup; *_index+=bmFtZQ.length; }; name=cast(string)bmFtZQ;
		if(_buffer.length>=*_index+bool.sizeof){ mainNode=peek!(bool, Endian.bigEndian)(_buffer, _index); }
		return this;
	}

}

struct ConnectionResponse {

	public enum ubyte ID = 1;

	public enum bool CLIENTBOUND = true;
	public enum bool SERVERBOUND = false;

	public bool protocolAccepted;
	public bool nameAccepted;

	public ubyte[] encode(bool writeId=true)() {
		ubyte[] _buffer;
		static if(writeId){ _buffer~=ID; }
		_buffer.length+=bool.sizeof; write!(bool, Endian.bigEndian)(_buffer, protocolAccepted, _buffer.length-bool.sizeof);
		_buffer.length+=bool.sizeof; write!(bool, Endian.bigEndian)(_buffer, nameAccepted, _buffer.length-bool.sizeof);
		return _buffer;
	}

	public typeof(this) decode(bool readId=true)(ubyte[] _buffer, size_t _index=0) {
		return this.decode!readId(_buffer, &_index);
	}

	public typeof(this) decode(bool readId=true)(ubyte[] _buffer, size_t* _index) {
		static if(readId){ typeof(ID) _id; if(_buffer.length>=*_index+ubyte.sizeof){ _id=peek!(ubyte, Endian.bigEndian)(_buffer, _index); } }
		if(_buffer.length>=*_index+bool.sizeof){ protocolAccepted=peek!(bool, Endian.bigEndian)(_buffer, _index); }
		if(_buffer.length>=*_index+bool.sizeof){ nameAccepted=peek!(bool, Endian.bigEndian)(_buffer, _index); }
		return this;
	}

}

struct Info {

	public enum ubyte ID = 2;

	public enum bool CLIENTBOUND = true;
	public enum bool SERVERBOUND = false;

	public long serverId;
	public bool onlineMode;
	public string displayName;
	public sul.protocol.hncom1.types.Game[] games;
	public uint online;
	public uint max;
	public string language;
	public string[] acceptedLanguages;
	public string[] nodes;
	public string socialJson;
	public string additionalJson;

	public ubyte[] encode(bool writeId=true)() {
		ubyte[] _buffer;
		static if(writeId){ _buffer~=ID; }
		_buffer.length+=long.sizeof; write!(long, Endian.bigEndian)(_buffer, serverId, _buffer.length-long.sizeof);
		_buffer.length+=bool.sizeof; write!(bool, Endian.bigEndian)(_buffer, onlineMode, _buffer.length-bool.sizeof);
		ubyte[] ZGlzcGxheU5hbWU=cast(ubyte[])displayName; _buffer~=varuint.encode(ZGlzcGxheU5hbWU.length.to!uint);_buffer~=ZGlzcGxheU5hbWU;
		_buffer~=varuint.encode(games.length.to!uint);foreach(Z2FtZXM;games){ Z2FtZXM.encode(_buffer); }
		_buffer~=varuint.encode(online);
		_buffer~=varuint.encode(max);
		ubyte[] bGFuZ3VhZ2U=cast(ubyte[])language; _buffer~=varuint.encode(bGFuZ3VhZ2U.length.to!uint);_buffer~=bGFuZ3VhZ2U;
		_buffer~=varuint.encode(acceptedLanguages.length.to!uint);foreach(YWNjZXB0ZWRMYW5n;acceptedLanguages){ ubyte[] WVdOalpYQjBaV1JN=cast(ubyte[])YWNjZXB0ZWRMYW5n; _buffer~=varuint.encode(WVdOalpYQjBaV1JN.length.to!uint);_buffer~=WVdOalpYQjBaV1JN; }
		_buffer~=varuint.encode(nodes.length.to!uint);foreach(bm9kZXM;nodes){ ubyte[] Ym05a1pYTQ=cast(ubyte[])bm9kZXM; _buffer~=varuint.encode(Ym05a1pYTQ.length.to!uint);_buffer~=Ym05a1pYTQ; }
		ubyte[] c29jaWFsSnNvbg=cast(ubyte[])socialJson; _buffer~=varuint.encode(c29jaWFsSnNvbg.length.to!uint);_buffer~=c29jaWFsSnNvbg;
		ubyte[] YWRkaXRpb25hbEpz=cast(ubyte[])additionalJson; _buffer~=varuint.encode(YWRkaXRpb25hbEpz.length.to!uint);_buffer~=YWRkaXRpb25hbEpz;
		return _buffer;
	}

	public typeof(this) decode(bool readId=true)(ubyte[] _buffer, size_t _index=0) {
		return this.decode!readId(_buffer, &_index);
	}

	public typeof(this) decode(bool readId=true)(ubyte[] _buffer, size_t* _index) {
		static if(readId){ typeof(ID) _id; if(_buffer.length>=*_index+ubyte.sizeof){ _id=peek!(ubyte, Endian.bigEndian)(_buffer, _index); } }
		if(_buffer.length>=*_index+long.sizeof){ serverId=peek!(long, Endian.bigEndian)(_buffer, _index); }
		if(_buffer.length>=*_index+bool.sizeof){ onlineMode=peek!(bool, Endian.bigEndian)(_buffer, _index); }
		ubyte[] ZGlzcGxheU5hbWU; ZGlzcGxheU5hbWU.length=varuint.decode(_buffer, *_index);if(_buffer.length>=*_index+ZGlzcGxheU5hbWU.length){ ZGlzcGxheU5hbWU=_buffer[*_index..*_index+ZGlzcGxheU5hbWU.length].dup; *_index+=ZGlzcGxheU5hbWU.length; }; displayName=cast(string)ZGlzcGxheU5hbWU;
		games.length=varuint.decode(_buffer, *_index);foreach(ref Z2FtZXM;games){ Z2FtZXM.decode(_buffer, _index); }
		online=varuint.decode(_buffer, *_index);
		max=varuint.decode(_buffer, *_index);
		ubyte[] bGFuZ3VhZ2U; bGFuZ3VhZ2U.length=varuint.decode(_buffer, *_index);if(_buffer.length>=*_index+bGFuZ3VhZ2U.length){ bGFuZ3VhZ2U=_buffer[*_index..*_index+bGFuZ3VhZ2U.length].dup; *_index+=bGFuZ3VhZ2U.length; }; language=cast(string)bGFuZ3VhZ2U;
		acceptedLanguages.length=varuint.decode(_buffer, *_index);foreach(ref YWNjZXB0ZWRMYW5n;acceptedLanguages){ ubyte[] WVdOalpYQjBaV1JN; WVdOalpYQjBaV1JN.length=varuint.decode(_buffer, *_index);if(_buffer.length>=*_index+WVdOalpYQjBaV1JN.length){ WVdOalpYQjBaV1JN=_buffer[*_index..*_index+WVdOalpYQjBaV1JN.length].dup; *_index+=WVdOalpYQjBaV1JN.length; }; YWNjZXB0ZWRMYW5n=cast(string)WVdOalpYQjBaV1JN; }
		nodes.length=varuint.decode(_buffer, *_index);foreach(ref bm9kZXM;nodes){ ubyte[] Ym05a1pYTQ; Ym05a1pYTQ.length=varuint.decode(_buffer, *_index);if(_buffer.length>=*_index+Ym05a1pYTQ.length){ Ym05a1pYTQ=_buffer[*_index..*_index+Ym05a1pYTQ.length].dup; *_index+=Ym05a1pYTQ.length; }; bm9kZXM=cast(string)Ym05a1pYTQ; }
		ubyte[] c29jaWFsSnNvbg; c29jaWFsSnNvbg.length=varuint.decode(_buffer, *_index);if(_buffer.length>=*_index+c29jaWFsSnNvbg.length){ c29jaWFsSnNvbg=_buffer[*_index..*_index+c29jaWFsSnNvbg.length].dup; *_index+=c29jaWFsSnNvbg.length; }; socialJson=cast(string)c29jaWFsSnNvbg;
		ubyte[] YWRkaXRpb25hbEpz; YWRkaXRpb25hbEpz.length=varuint.decode(_buffer, *_index);if(_buffer.length>=*_index+YWRkaXRpb25hbEpz.length){ YWRkaXRpb25hbEpz=_buffer[*_index..*_index+YWRkaXRpb25hbEpz.length].dup; *_index+=YWRkaXRpb25hbEpz.length; }; additionalJson=cast(string)YWRkaXRpb25hbEpz;
		return this;
	}

}

struct Ready {

	public enum ubyte ID = 3;

	public enum bool CLIENTBOUND = false;
	public enum bool SERVERBOUND = true;

	public sul.protocol.hncom1.types.Plugin[] plugins;

	public ubyte[] encode(bool writeId=true)() {
		ubyte[] _buffer;
		static if(writeId){ _buffer~=ID; }
		_buffer~=varuint.encode(plugins.length.to!uint);foreach(cGx1Z2lucw;plugins){ cGx1Z2lucw.encode(_buffer); }
		return _buffer;
	}

	public typeof(this) decode(bool readId=true)(ubyte[] _buffer, size_t _index=0) {
		return this.decode!readId(_buffer, &_index);
	}

	public typeof(this) decode(bool readId=true)(ubyte[] _buffer, size_t* _index) {
		static if(readId){ typeof(ID) _id; if(_buffer.length>=*_index+ubyte.sizeof){ _id=peek!(ubyte, Endian.bigEndian)(_buffer, _index); } }
		plugins.length=varuint.decode(_buffer, *_index);foreach(ref cGx1Z2lucw;plugins){ cGx1Z2lucw.decode(_buffer, _index); }
		return this;
	}

}
