/*
 * This file was automatically generated by sel-utils and
 * released under the GNU General Public License version 3.
 *
 * License: https://github.com/sel-project/sel-utils/blob/master/LICENSE
 * Repository: https://github.com/sel-project/sel-utils
 * Generated from https://github.com/sel-project/sel-utils/blob/master/xml/protocol/raknet8.xml
 */
/** @module sul/protocol/raknet8/encapsulated */

//import Types from 'types';

const Encapsulated = {

	ClientConnect: class extends Buffer {

		static get ID(){ return 9; }

		static get CLIENTBOUND(){ return false; }
		static get SERVERBOUND(){ return true; }

		constructor(clientId=0, pingId=0) {
			super();
			this.clientId = clientId;
			this.pingId = pingId;
		}

		/** @return {Uint8Array} */
		encode() {
			this._buffer = [];
			this.writeBigEndianByte(9);
			this.writeBigEndianLong(this.clientId);
			this.writeBigEndianLong(this.pingId);
			return new Uint8Array(this._buffer);
		}

		/** @param {Uint8Array}|{Array} buffer */
		decode(_buffer) {
			this._buffer = Array.from(_buffer);
			this._index = 0;
			var _id=this.readBigEndianByte();
			this.clientId=this.readBigEndianLong();
			this.pingId=this.readBigEndianLong();
			return this;
		}

		static fromBuffer(buffer) {
			return new Encapsulated.ClientConnect().decode(buffer);
		}

		/** @return {string} */
		toString() {
			return "ClientConnect(clientId: " + this.clientId + ", pingId: " + this.pingId + ")";
		}

	},

	ServerHandshake: class extends Buffer {

		static get ID(){ return 16; }

		static get CLIENTBOUND(){ return true; }
		static get SERVERBOUND(){ return false; }

		constructor(clientAddress=null, mtuLength=0, systemAddresses=[], pingId=0, serverId=0) {
			super();
			this.clientAddress = clientAddress;
			this.mtuLength = mtuLength;
			this.systemAddresses = systemAddresses;
			this.pingId = pingId;
			this.serverId = serverId;
		}

		/** @return {Uint8Array} */
		encode() {
			this._buffer = [];
			this.writeBigEndianByte(16);
			this.writeBytes(this.clientAddress.encode());
			this.writeBigEndianShort(this.mtuLength);
			for(var dghpcy5zexn0zw1b in this.systemAddresses){ this.writeBytes(this.systemAddresses[dghpcy5zexn0zw1b].encode()); }
			this.writeBigEndianLong(this.pingId);
			this.writeBigEndianLong(this.serverId);
			return new Uint8Array(this._buffer);
		}

		/** @param {Uint8Array}|{Array} buffer */
		decode(_buffer) {
			this._buffer = Array.from(_buffer);
			this._index = 0;
			var _id=this.readBigEndianByte();
			this.clientAddress=Types.Address.fromBuffer(this._buffer); this._buffer=this.clientAddress._buffer;
			this.mtuLength=this.readBigEndianShort();
			var bhroaxmuc3lzdgvt=10; this.systemAddresses=[]; for(var dghpcy5zexn0zw1b in this.systemAddresses){ this.systemAddresses[dghpcy5zexn0zw1b]=Types.Address.fromBuffer(this._buffer); this._buffer=this.systemAddresses[dghpcy5zexn0zw1b]._buffer; }
			this.pingId=this.readBigEndianLong();
			this.serverId=this.readBigEndianLong();
			return this;
		}

		static fromBuffer(buffer) {
			return new Encapsulated.ServerHandshake().decode(buffer);
		}

		/** @return {string} */
		toString() {
			return "ServerHandshake(clientAddress: " + this.clientAddress + ", mtuLength: " + this.mtuLength + ", systemAddresses: " + this.systemAddresses + ", pingId: " + this.pingId + ", serverId: " + this.serverId + ")";
		}

	},

	ClientHandshake: class extends Buffer {

		static get ID(){ return 19; }

		static get CLIENTBOUND(){ return false; }
		static get SERVERBOUND(){ return true; }

		constructor(clientAddress=null, systemAddresses=[], pingId=0, clientId=0) {
			super();
			this.clientAddress = clientAddress;
			this.systemAddresses = systemAddresses;
			this.pingId = pingId;
			this.clientId = clientId;
		}

		/** @return {Uint8Array} */
		encode() {
			this._buffer = [];
			this.writeBigEndianByte(19);
			this.writeBytes(this.clientAddress.encode());
			for(var dghpcy5zexn0zw1b in this.systemAddresses){ this.writeBytes(this.systemAddresses[dghpcy5zexn0zw1b].encode()); }
			this.writeBigEndianLong(this.pingId);
			this.writeBigEndianLong(this.clientId);
			return new Uint8Array(this._buffer);
		}

		/** @param {Uint8Array}|{Array} buffer */
		decode(_buffer) {
			this._buffer = Array.from(_buffer);
			this._index = 0;
			var _id=this.readBigEndianByte();
			this.clientAddress=Types.Address.fromBuffer(this._buffer); this._buffer=this.clientAddress._buffer;
			var bhroaxmuc3lzdgvt=10; this.systemAddresses=[]; for(var dghpcy5zexn0zw1b in this.systemAddresses){ this.systemAddresses[dghpcy5zexn0zw1b]=Types.Address.fromBuffer(this._buffer); this._buffer=this.systemAddresses[dghpcy5zexn0zw1b]._buffer; }
			this.pingId=this.readBigEndianLong();
			this.clientId=this.readBigEndianLong();
			return this;
		}

		static fromBuffer(buffer) {
			return new Encapsulated.ClientHandshake().decode(buffer);
		}

		/** @return {string} */
		toString() {
			return "ClientHandshake(clientAddress: " + this.clientAddress + ", systemAddresses: " + this.systemAddresses + ", pingId: " + this.pingId + ", clientId: " + this.clientId + ")";
		}

	},

	ClientCancelConnection: class extends Buffer {

		static get ID(){ return 21; }

		static get CLIENTBOUND(){ return false; }
		static get SERVERBOUND(){ return true; }

		constructor() {
			super();
		}

		/** @return {Uint8Array} */
		encode() {
			this._buffer = [];
			this.writeBigEndianByte(21);
			return new Uint8Array(this._buffer);
		}

		/** @param {Uint8Array}|{Array} buffer */
		decode(_buffer) {
			this._buffer = Array.from(_buffer);
			this._index = 0;
			var _id=this.readBigEndianByte();
			return this;
		}

		static fromBuffer(buffer) {
			return new Encapsulated.ClientCancelConnection().decode(buffer);
		}

		/** @return {string} */
		toString() {
			return "ClientCancelConnection()";
		}

	},

	Ping: class extends Buffer {

		static get ID(){ return 0; }

		static get CLIENTBOUND(){ return false; }
		static get SERVERBOUND(){ return true; }

		constructor(time=0) {
			super();
			this.time = time;
		}

		/** @return {Uint8Array} */
		encode() {
			this._buffer = [];
			this.writeBigEndianByte(0);
			this.writeBigEndianLong(this.time);
			return new Uint8Array(this._buffer);
		}

		/** @param {Uint8Array}|{Array} buffer */
		decode(_buffer) {
			this._buffer = Array.from(_buffer);
			this._index = 0;
			var _id=this.readBigEndianByte();
			this.time=this.readBigEndianLong();
			return this;
		}

		static fromBuffer(buffer) {
			return new Encapsulated.Ping().decode(buffer);
		}

		/** @return {string} */
		toString() {
			return "Ping(time: " + this.time + ")";
		}

	},

	Pong: class extends Buffer {

		static get ID(){ return 3; }

		static get CLIENTBOUND(){ return true; }
		static get SERVERBOUND(){ return false; }

		constructor(time=0) {
			super();
			this.time = time;
		}

		/** @return {Uint8Array} */
		encode() {
			this._buffer = [];
			this.writeBigEndianByte(3);
			this.writeBigEndianLong(this.time);
			return new Uint8Array(this._buffer);
		}

		/** @param {Uint8Array}|{Array} buffer */
		decode(_buffer) {
			this._buffer = Array.from(_buffer);
			this._index = 0;
			var _id=this.readBigEndianByte();
			this.time=this.readBigEndianLong();
			return this;
		}

		static fromBuffer(buffer) {
			return new Encapsulated.Pong().decode(buffer);
		}

		/** @return {string} */
		toString() {
			return "Pong(time: " + this.time + ")";
		}

	},

	Mcpe: class extends Buffer {

		static get ID(){ return 254; }

		static get CLIENTBOUND(){ return true; }
		static get SERVERBOUND(){ return true; }

		constructor(packet=null) {
			super();
			this.packet = packet;
		}

		/** @return {Uint8Array} */
		encode() {
			this._buffer = [];
			this.writeBigEndianByte(254);
			this.writeBytes(this.packet);
			return new Uint8Array(this._buffer);
		}

		/** @param {Uint8Array}|{Array} buffer */
		decode(_buffer) {
			this._buffer = Array.from(_buffer);
			this._index = 0;
			var _id=this.readBigEndianByte();
			this.packet=Array.from(this._buffer); this._buffer=[];
			return this;
		}

		static fromBuffer(buffer) {
			return new Encapsulated.Mcpe().decode(buffer);
		}

		/** @return {string} */
		toString() {
			return "Mcpe(packet: " + this.packet + ")";
		}

	},

}

//export { Encapsulated };
