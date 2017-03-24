/*
 * This file was automatically generated by sel-utils and
 * released under the GNU General Public License version 3.
 * 
 * License: https://github.com/sel-project/sel-utils/blob/master/LICENSE
 * Repository: https://github.com/sel-project/sel-utils
 * Generated from https://github.com/sel-project/sel-utils/blob/master/xml/protocol/hncom2.xml
 */
/** @module sul/protocol/hncom2/util */

//import Types from 'types';

/**
 * Packets used for sending more than one packet at once.
 */
const Util = {

	Uncompressed: class extends Buffer {

		static get ID(){ return 1; }

		static get CLIENTBOUND(){ return true; }
		static get SERVERBOUND(){ return true; }

		constructor(packets=[]) {
			super();
			this.packets = packets;
		}

		/** @return {Uint8Array} */
		encode() {
			this._buffer = [];
			this.writeBigEndianByte(1);
			this.writeVaruint(this.packets.length); for(var dhc5ynzr in this.packets){ this.writeVaruint(this.packets[dhc5ynzr].length); this.writeBytes(this.packets[dhc5ynzr]); }
			return new Uint8Array(this._buffer);
		}

		/** @param {(Uint8Array|Array)} buffer */
		decode(_buffer) {
			this._buffer = Array.from(_buffer);
			var _id=this.readBigEndianByte();
			var aramcfav=this.readVaruint(); this.packets=[]; for(var dhc5ynzr=0;dhc5ynzr<aramcfav;dhc5ynzr++){ var aramcfav=this.readVaruint(); this.packets[dhc5ynzr]=this.readBytes(aramcfav); }
			return this;
		}

		/** @param {(Uint8Array|Array)} buffer */
		static fromBuffer(buffer) {
			return new Util.Uncompressed().decode(buffer);
		}

		/** @return {string} */
		toString() {
			return "Uncompressed(packets: " + this.packets + ")";
		}

	},

	Compressed: class extends Buffer {

		static get ID(){ return 2; }

		static get CLIENTBOUND(){ return true; }
		static get SERVERBOUND(){ return true; }

		constructor(size=0, payload=null) {
			super();
			this.size = size;
			this.payload = payload;
		}

		/** @return {Uint8Array} */
		encode() {
			this._buffer = [];
			this.writeBigEndianByte(2);
			this.writeVaruint(this.size);
			this.writeBytes(this.payload);
			return new Uint8Array(this._buffer);
		}

		/** @param {(Uint8Array|Array)} buffer */
		decode(_buffer) {
			this._buffer = Array.from(_buffer);
			var _id=this.readBigEndianByte();
			this.size=this.readVaruint();
			this.payload=Array.from(this._buffer); this._buffer=[];
			return this;
		}

		/** @param {(Uint8Array|Array)} buffer */
		static fromBuffer(buffer) {
			return new Util.Compressed().decode(buffer);
		}

		/** @return {string} */
		toString() {
			return "Compressed(size: " + this.size + ", payload: " + this.payload + ")";
		}

	},

}

//export { Util };
