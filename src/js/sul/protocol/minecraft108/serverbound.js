/*
 * This file was automatically generated by sel-utils and
 * released under the GNU General Public License version 3.
 *
 * License: https://github.com/sel-project/sel-utils/blob/master/LICENSE
 * Repository: https://github.com/sel-project/sel-utils
 * Generated from https://github.com/sel-project/sel-utils/blob/master/xml/protocol/minecraft108.xml
 */
/** @module sul/protocol/minecraft108/serverbound */

//import Types from 'types';

const Serverbound = {

	TeleportConfirm: class extends Buffer {

		static get ID(){ return 0; }

		static get CLIENTBOUND(){ return false; }
		static get SERVERBOUND(){ return true; }

		constructor(teleportId=0) {
			super();
			this.teleportId = teleportId;
		}

		/** @return {Uint8Array} */
		encode() {
			this._buffer = [];
			this.writeVaruint(0);
			this.writeVaruint(this.teleportId);
			return new Uint8Array(this._buffer);
		}

		/** @param {Uint8Array}|{Array} buffer */
		decode(_buffer) {
			this._buffer = Array.from(_buffer);
			this._index = 0;
			var _id=this.readVaruint();
			this.teleportId=this.readVaruint();
			return this;
		}

		static fromBuffer(buffer) {
			return new Serverbound.TeleportConfirm().decode(buffer);
		}

		/** @return {string} */
		toString() {
			return "TeleportConfirm(teleportId: " + this.teleportId + ")";
		}

	},

	TabComplete: class extends Buffer {

		static get ID(){ return 1; }

		static get CLIENTBOUND(){ return false; }
		static get SERVERBOUND(){ return true; }

		constructor(text="", command=false, hasPosition=false, block=0) {
			super();
			this.text = text;
			this.command = command;
			this.hasPosition = hasPosition;
			this.block = block;
		}

		/** @return {Uint8Array} */
		encode() {
			this._buffer = [];
			this.writeVaruint(1);
			var dghpcy50zxh0=this.encodeString(this.text); this.writeVaruint(dghpcy50zxh0.length); this.writeBytes(dghpcy50zxh0);
			this.writeBigEndianByte(this.command?1:0);
			this.writeBigEndianByte(this.hasPosition?1:0);
			if(hasPosition==true){ this.writeBigEndianLong(this.block); }
			return new Uint8Array(this._buffer);
		}

		/** @param {Uint8Array}|{Array} buffer */
		decode(_buffer) {
			this._buffer = Array.from(_buffer);
			this._index = 0;
			var _id=this.readVaruint();
			this.text=this.decodeString(this.readBytes(this.readVaruint()));
			this.command=this.readBigEndianByte()!==0;
			this.hasPosition=this.readBigEndianByte()!==0;
			if(hasPosition==true){ this.block=this.readBigEndianLong(); }
			return this;
		}

		static fromBuffer(buffer) {
			return new Serverbound.TabComplete().decode(buffer);
		}

		/** @return {string} */
		toString() {
			return "TabComplete(text: " + this.text + ", command: " + this.command + ", hasPosition: " + this.hasPosition + ", block: " + this.block + ")";
		}

	},

	ChatMessage: class extends Buffer {

		static get ID(){ return 2; }

		static get CLIENTBOUND(){ return false; }
		static get SERVERBOUND(){ return true; }

		constructor(text="") {
			super();
			this.text = text;
		}

		/** @return {Uint8Array} */
		encode() {
			this._buffer = [];
			this.writeVaruint(2);
			var dghpcy50zxh0=this.encodeString(this.text); this.writeVaruint(dghpcy50zxh0.length); this.writeBytes(dghpcy50zxh0);
			return new Uint8Array(this._buffer);
		}

		/** @param {Uint8Array}|{Array} buffer */
		decode(_buffer) {
			this._buffer = Array.from(_buffer);
			this._index = 0;
			var _id=this.readVaruint();
			this.text=this.decodeString(this.readBytes(this.readVaruint()));
			return this;
		}

		static fromBuffer(buffer) {
			return new Serverbound.ChatMessage().decode(buffer);
		}

		/** @return {string} */
		toString() {
			return "ChatMessage(text: " + this.text + ")";
		}

	},

	ClientStatus: class extends Buffer {

		static get ID(){ return 3; }

		static get CLIENTBOUND(){ return false; }
		static get SERVERBOUND(){ return true; }

		// action
		static get RESPAWN(){ return 0; }
		static get REQUEST_STATS(){ return 1; }
		static get OPEN_INVENTORY(){ return 2; }

		constructor(action=0) {
			super();
			this.action = action;
		}

		/** @return {Uint8Array} */
		encode() {
			this._buffer = [];
			this.writeVaruint(3);
			this.writeVaruint(this.action);
			return new Uint8Array(this._buffer);
		}

		/** @param {Uint8Array}|{Array} buffer */
		decode(_buffer) {
			this._buffer = Array.from(_buffer);
			this._index = 0;
			var _id=this.readVaruint();
			this.action=this.readVaruint();
			return this;
		}

		static fromBuffer(buffer) {
			return new Serverbound.ClientStatus().decode(buffer);
		}

		/** @return {string} */
		toString() {
			return "ClientStatus(action: " + this.action + ")";
		}

	},

	ClientSettings: class extends Buffer {

		static get ID(){ return 4; }

		static get CLIENTBOUND(){ return false; }
		static get SERVERBOUND(){ return true; }

		// chat mode
		static get ENABLED(){ return 0; }
		static get COMMANDS_ONLY(){ return 1; }
		static get DISABLED(){ return 2; }

		// displayed skin parts
		static get CAPE(){ return 1; }
		static get JACKET(){ return 2; }
		static get LEFT_SLEEVE(){ return 4; }
		static get RIGHT_SLEEVE(){ return 8; }
		static get LEFT_PANTS(){ return 16; }
		static get RIGHT_PANTS(){ return 32; }
		static get HAT(){ return 64; }

		// main hand
		static get RIGHT(){ return 0; }
		static get LEFT(){ return 1; }

		constructor(language="", viewDistance=0, chatMode=0, chatColors=false, displayedSkinParts=0, mainHand=0) {
			super();
			this.language = language;
			this.viewDistance = viewDistance;
			this.chatMode = chatMode;
			this.chatColors = chatColors;
			this.displayedSkinParts = displayedSkinParts;
			this.mainHand = mainHand;
		}

		/** @return {Uint8Array} */
		encode() {
			this._buffer = [];
			this.writeVaruint(4);
			var dghpcy5syw5ndwfn=this.encodeString(this.language); this.writeVaruint(dghpcy5syw5ndwfn.length); this.writeBytes(dghpcy5syw5ndwfn);
			this.writeBigEndianByte(this.viewDistance);
			this.writeVaruint(this.chatMode);
			this.writeBigEndianByte(this.chatColors?1:0);
			this.writeBigEndianByte(this.displayedSkinParts);
			this.writeBigEndianByte(this.mainHand);
			return new Uint8Array(this._buffer);
		}

		/** @param {Uint8Array}|{Array} buffer */
		decode(_buffer) {
			this._buffer = Array.from(_buffer);
			this._index = 0;
			var _id=this.readVaruint();
			this.language=this.decodeString(this.readBytes(this.readVaruint()));
			this.viewDistance=this.readBigEndianByte();
			this.chatMode=this.readVaruint();
			this.chatColors=this.readBigEndianByte()!==0;
			this.displayedSkinParts=this.readBigEndianByte();
			this.mainHand=this.readBigEndianByte();
			return this;
		}

		static fromBuffer(buffer) {
			return new Serverbound.ClientSettings().decode(buffer);
		}

		/** @return {string} */
		toString() {
			return "ClientSettings(language: " + this.language + ", viewDistance: " + this.viewDistance + ", chatMode: " + this.chatMode + ", chatColors: " + this.chatColors + ", displayedSkinParts: " + this.displayedSkinParts + ", mainHand: " + this.mainHand + ")";
		}

	},

	ConfirmTransaction: class extends Buffer {

		static get ID(){ return 5; }

		static get CLIENTBOUND(){ return false; }
		static get SERVERBOUND(){ return true; }

		constructor(window=0, action=0, accepted=false) {
			super();
			this.window = window;
			this.action = action;
			this.accepted = accepted;
		}

		/** @return {Uint8Array} */
		encode() {
			this._buffer = [];
			this.writeVaruint(5);
			this.writeBigEndianByte(this.window);
			this.writeBigEndianShort(this.action);
			this.writeBigEndianByte(this.accepted?1:0);
			return new Uint8Array(this._buffer);
		}

		/** @param {Uint8Array}|{Array} buffer */
		decode(_buffer) {
			this._buffer = Array.from(_buffer);
			this._index = 0;
			var _id=this.readVaruint();
			this.window=this.readBigEndianByte();
			this.action=this.readBigEndianShort();
			this.accepted=this.readBigEndianByte()!==0;
			return this;
		}

		static fromBuffer(buffer) {
			return new Serverbound.ConfirmTransaction().decode(buffer);
		}

		/** @return {string} */
		toString() {
			return "ConfirmTransaction(window: " + this.window + ", action: " + this.action + ", accepted: " + this.accepted + ")";
		}

	},

	EnchantItem: class extends Buffer {

		static get ID(){ return 6; }

		static get CLIENTBOUND(){ return false; }
		static get SERVERBOUND(){ return true; }

		constructor(window=0, enchantment=0) {
			super();
			this.window = window;
			this.enchantment = enchantment;
		}

		/** @return {Uint8Array} */
		encode() {
			this._buffer = [];
			this.writeVaruint(6);
			this.writeBigEndianByte(this.window);
			this.writeBigEndianByte(this.enchantment);
			return new Uint8Array(this._buffer);
		}

		/** @param {Uint8Array}|{Array} buffer */
		decode(_buffer) {
			this._buffer = Array.from(_buffer);
			this._index = 0;
			var _id=this.readVaruint();
			this.window=this.readBigEndianByte();
			this.enchantment=this.readBigEndianByte();
			return this;
		}

		static fromBuffer(buffer) {
			return new Serverbound.EnchantItem().decode(buffer);
		}

		/** @return {string} */
		toString() {
			return "EnchantItem(window: " + this.window + ", enchantment: " + this.enchantment + ")";
		}

	},

	ClickWindow: class extends Buffer {

		static get ID(){ return 7; }

		static get CLIENTBOUND(){ return false; }
		static get SERVERBOUND(){ return true; }

		constructor(window=0, slot=0, button=0, action=0, mode=0, clickedItem=null) {
			super();
			this.window = window;
			this.slot = slot;
			this.button = button;
			this.action = action;
			this.mode = mode;
			this.clickedItem = clickedItem;
		}

		/** @return {Uint8Array} */
		encode() {
			this._buffer = [];
			this.writeVaruint(7);
			this.writeBigEndianByte(this.window);
			this.writeBigEndianShort(this.slot);
			this.writeBigEndianByte(this.button);
			this.writeBigEndianShort(this.action);
			this.writeVaruint(this.mode);
			this.writeBytes(this.clickedItem.encode());
			return new Uint8Array(this._buffer);
		}

		/** @param {Uint8Array}|{Array} buffer */
		decode(_buffer) {
			this._buffer = Array.from(_buffer);
			this._index = 0;
			var _id=this.readVaruint();
			this.window=this.readBigEndianByte();
			this.slot=this.readBigEndianShort();
			this.button=this.readBigEndianByte();
			this.action=this.readBigEndianShort();
			this.mode=this.readVaruint();
			this.clickedItem=Types.Slot.fromBuffer(this._buffer); this._buffer=this.clickedItem._buffer;
			return this;
		}

		static fromBuffer(buffer) {
			return new Serverbound.ClickWindow().decode(buffer);
		}

		/** @return {string} */
		toString() {
			return "ClickWindow(window: " + this.window + ", slot: " + this.slot + ", button: " + this.button + ", action: " + this.action + ", mode: " + this.mode + ", clickedItem: " + this.clickedItem + ")";
		}

	},

	CloseWindow: class extends Buffer {

		static get ID(){ return 8; }

		static get CLIENTBOUND(){ return false; }
		static get SERVERBOUND(){ return true; }

		constructor(window=0) {
			super();
			this.window = window;
		}

		/** @return {Uint8Array} */
		encode() {
			this._buffer = [];
			this.writeVaruint(8);
			this.writeBigEndianByte(this.window);
			return new Uint8Array(this._buffer);
		}

		/** @param {Uint8Array}|{Array} buffer */
		decode(_buffer) {
			this._buffer = Array.from(_buffer);
			this._index = 0;
			var _id=this.readVaruint();
			this.window=this.readBigEndianByte();
			return this;
		}

		static fromBuffer(buffer) {
			return new Serverbound.CloseWindow().decode(buffer);
		}

		/** @return {string} */
		toString() {
			return "CloseWindow(window: " + this.window + ")";
		}

	},

	PluginMessage: class extends Buffer {

		static get ID(){ return 9; }

		static get CLIENTBOUND(){ return false; }
		static get SERVERBOUND(){ return true; }

		constructor(channel="", data=null) {
			super();
			this.channel = channel;
			this.data = data;
		}

		/** @return {Uint8Array} */
		encode() {
			this._buffer = [];
			this.writeVaruint(9);
			var dghpcy5jagfubmvs=this.encodeString(this.channel); this.writeVaruint(dghpcy5jagfubmvs.length); this.writeBytes(dghpcy5jagfubmvs);
			this.writeBytes(this.data);
			return new Uint8Array(this._buffer);
		}

		/** @param {Uint8Array}|{Array} buffer */
		decode(_buffer) {
			this._buffer = Array.from(_buffer);
			this._index = 0;
			var _id=this.readVaruint();
			this.channel=this.decodeString(this.readBytes(this.readVaruint()));
			this.data=Array.from(this._buffer); this._buffer=[];
			return this;
		}

		static fromBuffer(buffer) {
			return new Serverbound.PluginMessage().decode(buffer);
		}

		/** @return {string} */
		toString() {
			return "PluginMessage(channel: " + this.channel + ", data: " + this.data + ")";
		}

	},

	UseEntity: class extends Buffer {

		static get ID(){ return 10; }

		static get CLIENTBOUND(){ return false; }
		static get SERVERBOUND(){ return true; }

		// type
		static get INTERACT(){ return 0; }
		static get ATTACK(){ return 1; }
		static get INTERACT_AT(){ return 2; }

		// hand
		static get MAIN_HAND(){ return 0; }
		static get OFF_HAND(){ return 1; }

		constructor(target=0, type=0, targetPosition={x:0,y:0,z:0}, hand=0) {
			super();
			this.target = target;
			this.type = type;
			this.targetPosition = targetPosition;
			this.hand = hand;
		}

		/** @return {Uint8Array} */
		encode() {
			this._buffer = [];
			this.writeVaruint(10);
			this.writeVaruint(this.target);
			this.writeVaruint(this.type);
			if(type==2){ this.writeBigEndianFloat(this.targetPosition.x); this.writeBigEndianFloat(this.targetPosition.y); this.writeBigEndianFloat(this.targetPosition.z); }
			if(type==2){ this.writeVaruint(this.hand); }
			return new Uint8Array(this._buffer);
		}

		/** @param {Uint8Array}|{Array} buffer */
		decode(_buffer) {
			this._buffer = Array.from(_buffer);
			this._index = 0;
			var _id=this.readVaruint();
			this.target=this.readVaruint();
			this.type=this.readVaruint();
			if(type==2){ this.targetPosition={}; this.targetPosition.x=this.readBigEndianFloat(); this.targetPosition.y=this.readBigEndianFloat(); this.targetPosition.z=this.readBigEndianFloat(); }
			if(type==2){ this.hand=this.readVaruint(); }
			return this;
		}

		static fromBuffer(buffer) {
			return new Serverbound.UseEntity().decode(buffer);
		}

		/** @return {string} */
		toString() {
			return "UseEntity(target: " + this.target + ", type: " + this.type + ", targetPosition: " + this.targetPosition + ", hand: " + this.hand + ")";
		}

	},

	KeepAlive: class extends Buffer {

		static get ID(){ return 11; }

		static get CLIENTBOUND(){ return false; }
		static get SERVERBOUND(){ return true; }

		constructor(id=0) {
			super();
			this.id = id;
		}

		/** @return {Uint8Array} */
		encode() {
			this._buffer = [];
			this.writeVaruint(11);
			this.writeVaruint(this.id);
			return new Uint8Array(this._buffer);
		}

		/** @param {Uint8Array}|{Array} buffer */
		decode(_buffer) {
			this._buffer = Array.from(_buffer);
			this._index = 0;
			var _id=this.readVaruint();
			this.id=this.readVaruint();
			return this;
		}

		static fromBuffer(buffer) {
			return new Serverbound.KeepAlive().decode(buffer);
		}

		/** @return {string} */
		toString() {
			return "KeepAlive(id: " + this.id + ")";
		}

	},

	PlayerPosition: class extends Buffer {

		static get ID(){ return 12; }

		static get CLIENTBOUND(){ return false; }
		static get SERVERBOUND(){ return true; }

		constructor(position={x:0,y:0,z:0}, onGround=false) {
			super();
			this.position = position;
			this.onGround = onGround;
		}

		/** @return {Uint8Array} */
		encode() {
			this._buffer = [];
			this.writeVaruint(12);
			this.writeBigEndianDouble(this.position.x); this.writeBigEndianDouble(this.position.y); this.writeBigEndianDouble(this.position.z);
			this.writeBigEndianByte(this.onGround?1:0);
			return new Uint8Array(this._buffer);
		}

		/** @param {Uint8Array}|{Array} buffer */
		decode(_buffer) {
			this._buffer = Array.from(_buffer);
			this._index = 0;
			var _id=this.readVaruint();
			this.position={}; this.position.x=this.readBigEndianDouble(); this.position.y=this.readBigEndianDouble(); this.position.z=this.readBigEndianDouble();
			this.onGround=this.readBigEndianByte()!==0;
			return this;
		}

		static fromBuffer(buffer) {
			return new Serverbound.PlayerPosition().decode(buffer);
		}

		/** @return {string} */
		toString() {
			return "PlayerPosition(position: " + this.position + ", onGround: " + this.onGround + ")";
		}

	},

	PlayerPositionAndLook: class extends Buffer {

		static get ID(){ return 13; }

		static get CLIENTBOUND(){ return false; }
		static get SERVERBOUND(){ return true; }

		constructor(position={x:0,y:0,z:0}, yaw=.0, pitch=.0, onGround=false) {
			super();
			this.position = position;
			this.yaw = yaw;
			this.pitch = pitch;
			this.onGround = onGround;
		}

		/** @return {Uint8Array} */
		encode() {
			this._buffer = [];
			this.writeVaruint(13);
			this.writeBigEndianDouble(this.position.x); this.writeBigEndianDouble(this.position.y); this.writeBigEndianDouble(this.position.z);
			this.writeBigEndianFloat(this.yaw);
			this.writeBigEndianFloat(this.pitch);
			this.writeBigEndianByte(this.onGround?1:0);
			return new Uint8Array(this._buffer);
		}

		/** @param {Uint8Array}|{Array} buffer */
		decode(_buffer) {
			this._buffer = Array.from(_buffer);
			this._index = 0;
			var _id=this.readVaruint();
			this.position={}; this.position.x=this.readBigEndianDouble(); this.position.y=this.readBigEndianDouble(); this.position.z=this.readBigEndianDouble();
			this.yaw=this.readBigEndianFloat();
			this.pitch=this.readBigEndianFloat();
			this.onGround=this.readBigEndianByte()!==0;
			return this;
		}

		static fromBuffer(buffer) {
			return new Serverbound.PlayerPositionAndLook().decode(buffer);
		}

		/** @return {string} */
		toString() {
			return "PlayerPositionAndLook(position: " + this.position + ", yaw: " + this.yaw + ", pitch: " + this.pitch + ", onGround: " + this.onGround + ")";
		}

	},

	PlayerLook: class extends Buffer {

		static get ID(){ return 14; }

		static get CLIENTBOUND(){ return false; }
		static get SERVERBOUND(){ return true; }

		constructor(yaw=.0, pitch=.0, onGround=false) {
			super();
			this.yaw = yaw;
			this.pitch = pitch;
			this.onGround = onGround;
		}

		/** @return {Uint8Array} */
		encode() {
			this._buffer = [];
			this.writeVaruint(14);
			this.writeBigEndianFloat(this.yaw);
			this.writeBigEndianFloat(this.pitch);
			this.writeBigEndianByte(this.onGround?1:0);
			return new Uint8Array(this._buffer);
		}

		/** @param {Uint8Array}|{Array} buffer */
		decode(_buffer) {
			this._buffer = Array.from(_buffer);
			this._index = 0;
			var _id=this.readVaruint();
			this.yaw=this.readBigEndianFloat();
			this.pitch=this.readBigEndianFloat();
			this.onGround=this.readBigEndianByte()!==0;
			return this;
		}

		static fromBuffer(buffer) {
			return new Serverbound.PlayerLook().decode(buffer);
		}

		/** @return {string} */
		toString() {
			return "PlayerLook(yaw: " + this.yaw + ", pitch: " + this.pitch + ", onGround: " + this.onGround + ")";
		}

	},

	Player: class extends Buffer {

		static get ID(){ return 15; }

		static get CLIENTBOUND(){ return false; }
		static get SERVERBOUND(){ return true; }

		constructor(onGround=false) {
			super();
			this.onGround = onGround;
		}

		/** @return {Uint8Array} */
		encode() {
			this._buffer = [];
			this.writeVaruint(15);
			this.writeBigEndianByte(this.onGround?1:0);
			return new Uint8Array(this._buffer);
		}

		/** @param {Uint8Array}|{Array} buffer */
		decode(_buffer) {
			this._buffer = Array.from(_buffer);
			this._index = 0;
			var _id=this.readVaruint();
			this.onGround=this.readBigEndianByte()!==0;
			return this;
		}

		static fromBuffer(buffer) {
			return new Serverbound.Player().decode(buffer);
		}

		/** @return {string} */
		toString() {
			return "Player(onGround: " + this.onGround + ")";
		}

	},

	VehicleMove: class extends Buffer {

		static get ID(){ return 16; }

		static get CLIENTBOUND(){ return false; }
		static get SERVERBOUND(){ return true; }

		constructor(position={x:0,y:0,z:0}, yaw=.0, pitch=.0) {
			super();
			this.position = position;
			this.yaw = yaw;
			this.pitch = pitch;
		}

		/** @return {Uint8Array} */
		encode() {
			this._buffer = [];
			this.writeVaruint(16);
			this.writeBigEndianDouble(this.position.x); this.writeBigEndianDouble(this.position.y); this.writeBigEndianDouble(this.position.z);
			this.writeBigEndianFloat(this.yaw);
			this.writeBigEndianFloat(this.pitch);
			return new Uint8Array(this._buffer);
		}

		/** @param {Uint8Array}|{Array} buffer */
		decode(_buffer) {
			this._buffer = Array.from(_buffer);
			this._index = 0;
			var _id=this.readVaruint();
			this.position={}; this.position.x=this.readBigEndianDouble(); this.position.y=this.readBigEndianDouble(); this.position.z=this.readBigEndianDouble();
			this.yaw=this.readBigEndianFloat();
			this.pitch=this.readBigEndianFloat();
			return this;
		}

		static fromBuffer(buffer) {
			return new Serverbound.VehicleMove().decode(buffer);
		}

		/** @return {string} */
		toString() {
			return "VehicleMove(position: " + this.position + ", yaw: " + this.yaw + ", pitch: " + this.pitch + ")";
		}

	},

	SteerBoat: class extends Buffer {

		static get ID(){ return 17; }

		static get CLIENTBOUND(){ return false; }
		static get SERVERBOUND(){ return true; }

		constructor(rightPaddleTurning=false, leftPaddleTurning=false) {
			super();
			this.rightPaddleTurning = rightPaddleTurning;
			this.leftPaddleTurning = leftPaddleTurning;
		}

		/** @return {Uint8Array} */
		encode() {
			this._buffer = [];
			this.writeVaruint(17);
			this.writeBigEndianByte(this.rightPaddleTurning?1:0);
			this.writeBigEndianByte(this.leftPaddleTurning?1:0);
			return new Uint8Array(this._buffer);
		}

		/** @param {Uint8Array}|{Array} buffer */
		decode(_buffer) {
			this._buffer = Array.from(_buffer);
			this._index = 0;
			var _id=this.readVaruint();
			this.rightPaddleTurning=this.readBigEndianByte()!==0;
			this.leftPaddleTurning=this.readBigEndianByte()!==0;
			return this;
		}

		static fromBuffer(buffer) {
			return new Serverbound.SteerBoat().decode(buffer);
		}

		/** @return {string} */
		toString() {
			return "SteerBoat(rightPaddleTurning: " + this.rightPaddleTurning + ", leftPaddleTurning: " + this.leftPaddleTurning + ")";
		}

	},

	PlayerAbilities: class extends Buffer {

		static get ID(){ return 18; }

		static get CLIENTBOUND(){ return false; }
		static get SERVERBOUND(){ return true; }

		// flags
		static get CREATIVE_MODE(){ return 1; }
		static get FLYING(){ return 2; }
		static get ALLOW_FLYING(){ return 4; }
		static get INVINCIBLE(){ return 8; }

		constructor(flags=0, flyingSpeed=.0, walkingSpeed=.0) {
			super();
			this.flags = flags;
			this.flyingSpeed = flyingSpeed;
			this.walkingSpeed = walkingSpeed;
		}

		/** @return {Uint8Array} */
		encode() {
			this._buffer = [];
			this.writeVaruint(18);
			this.writeBigEndianByte(this.flags);
			this.writeBigEndianFloat(this.flyingSpeed);
			this.writeBigEndianFloat(this.walkingSpeed);
			return new Uint8Array(this._buffer);
		}

		/** @param {Uint8Array}|{Array} buffer */
		decode(_buffer) {
			this._buffer = Array.from(_buffer);
			this._index = 0;
			var _id=this.readVaruint();
			this.flags=this.readBigEndianByte();
			this.flyingSpeed=this.readBigEndianFloat();
			this.walkingSpeed=this.readBigEndianFloat();
			return this;
		}

		static fromBuffer(buffer) {
			return new Serverbound.PlayerAbilities().decode(buffer);
		}

		/** @return {string} */
		toString() {
			return "PlayerAbilities(flags: " + this.flags + ", flyingSpeed: " + this.flyingSpeed + ", walkingSpeed: " + this.walkingSpeed + ")";
		}

	},

	PlayerDigging: class extends Buffer {

		static get ID(){ return 19; }

		static get CLIENTBOUND(){ return false; }
		static get SERVERBOUND(){ return true; }

		// status
		static get START_DIGGING(){ return 0; }
		static get CANCEL_DIGGING(){ return 1; }
		static get FINISH_DIGGING(){ return 2; }
		static get DROP_ITEM_STACK(){ return 3; }
		static get DROP_ITEM(){ return 4; }
		static get SHOOT_ARROW(){ return 5; }
		static get FINISH_EATING(){ return 5; }
		static get SWAP_ITEM_IN_HAND(){ return 6; }

		constructor(status=0, position=0, face=0) {
			super();
			this.status = status;
			this.position = position;
			this.face = face;
		}

		/** @return {Uint8Array} */
		encode() {
			this._buffer = [];
			this.writeVaruint(19);
			this.writeVaruint(this.status);
			this.writeBigEndianLong(this.position);
			this.writeBigEndianByte(this.face);
			return new Uint8Array(this._buffer);
		}

		/** @param {Uint8Array}|{Array} buffer */
		decode(_buffer) {
			this._buffer = Array.from(_buffer);
			this._index = 0;
			var _id=this.readVaruint();
			this.status=this.readVaruint();
			this.position=this.readBigEndianLong();
			this.face=this.readBigEndianByte();
			return this;
		}

		static fromBuffer(buffer) {
			return new Serverbound.PlayerDigging().decode(buffer);
		}

		/** @return {string} */
		toString() {
			return "PlayerDigging(status: " + this.status + ", position: " + this.position + ", face: " + this.face + ")";
		}

	},

	EntityAction: class extends Buffer {

		static get ID(){ return 20; }

		static get CLIENTBOUND(){ return false; }
		static get SERVERBOUND(){ return true; }

		// action
		static get START_SNEAKING(){ return 0; }
		static get STOP_SNEAKING(){ return 1; }
		static get LEAVE_BED(){ return 2; }
		static get START_SPRINTING(){ return 3; }
		static get STOP_SPRINTING(){ return 4; }
		static get START_HORSE_JUMP(){ return 5; }
		static get STOP_HORSE_JUMP(){ return 6; }
		static get OPEN_HORSE_INVENTORY(){ return 7; }
		static get START_ELYTRA_FLYING(){ return 8; }

		constructor(entityId=0, action=0, jumpBoost=0) {
			super();
			this.entityId = entityId;
			this.action = action;
			this.jumpBoost = jumpBoost;
		}

		/** @return {Uint8Array} */
		encode() {
			this._buffer = [];
			this.writeVaruint(20);
			this.writeVaruint(this.entityId);
			this.writeVaruint(this.action);
			if(action==5){ this.writeVaruint(this.jumpBoost); }
			return new Uint8Array(this._buffer);
		}

		/** @param {Uint8Array}|{Array} buffer */
		decode(_buffer) {
			this._buffer = Array.from(_buffer);
			this._index = 0;
			var _id=this.readVaruint();
			this.entityId=this.readVaruint();
			this.action=this.readVaruint();
			if(action==5){ this.jumpBoost=this.readVaruint(); }
			return this;
		}

		static fromBuffer(buffer) {
			return new Serverbound.EntityAction().decode(buffer);
		}

		/** @return {string} */
		toString() {
			return "EntityAction(entityId: " + this.entityId + ", action: " + this.action + ", jumpBoost: " + this.jumpBoost + ")";
		}

	},

	SteerVehicle: class extends Buffer {

		static get ID(){ return 21; }

		static get CLIENTBOUND(){ return false; }
		static get SERVERBOUND(){ return true; }

		// flags
		static get JUMP(){ return 1; }
		static get UNMOUNT(){ return 2; }

		constructor(sideways=.0, forward=.0, flags=0) {
			super();
			this.sideways = sideways;
			this.forward = forward;
			this.flags = flags;
		}

		/** @return {Uint8Array} */
		encode() {
			this._buffer = [];
			this.writeVaruint(21);
			this.writeBigEndianFloat(this.sideways);
			this.writeBigEndianFloat(this.forward);
			this.writeBigEndianByte(this.flags);
			return new Uint8Array(this._buffer);
		}

		/** @param {Uint8Array}|{Array} buffer */
		decode(_buffer) {
			this._buffer = Array.from(_buffer);
			this._index = 0;
			var _id=this.readVaruint();
			this.sideways=this.readBigEndianFloat();
			this.forward=this.readBigEndianFloat();
			this.flags=this.readBigEndianByte();
			return this;
		}

		static fromBuffer(buffer) {
			return new Serverbound.SteerVehicle().decode(buffer);
		}

		/** @return {string} */
		toString() {
			return "SteerVehicle(sideways: " + this.sideways + ", forward: " + this.forward + ", flags: " + this.flags + ")";
		}

	},

	ResourcePackStatus: class extends Buffer {

		static get ID(){ return 22; }

		static get CLIENTBOUND(){ return false; }
		static get SERVERBOUND(){ return true; }

		// result
		static get LOADED(){ return 0; }
		static get DECLINED(){ return 1; }
		static get FAILED(){ return 2; }
		static get ACCEPTED(){ return 3; }

		constructor(hash="", result=0) {
			super();
			this.hash = hash;
			this.result = result;
		}

		/** @return {Uint8Array} */
		encode() {
			this._buffer = [];
			this.writeVaruint(22);
			var dghpcy5oyxno=this.encodeString(this.hash); this.writeVaruint(dghpcy5oyxno.length); this.writeBytes(dghpcy5oyxno);
			this.writeVaruint(this.result);
			return new Uint8Array(this._buffer);
		}

		/** @param {Uint8Array}|{Array} buffer */
		decode(_buffer) {
			this._buffer = Array.from(_buffer);
			this._index = 0;
			var _id=this.readVaruint();
			this.hash=this.decodeString(this.readBytes(this.readVaruint()));
			this.result=this.readVaruint();
			return this;
		}

		static fromBuffer(buffer) {
			return new Serverbound.ResourcePackStatus().decode(buffer);
		}

		/** @return {string} */
		toString() {
			return "ResourcePackStatus(hash: " + this.hash + ", result: " + this.result + ")";
		}

	},

	HeldItemChange: class extends Buffer {

		static get ID(){ return 23; }

		static get CLIENTBOUND(){ return false; }
		static get SERVERBOUND(){ return true; }

		constructor(slot=0) {
			super();
			this.slot = slot;
		}

		/** @return {Uint8Array} */
		encode() {
			this._buffer = [];
			this.writeVaruint(23);
			this.writeBigEndianShort(this.slot);
			return new Uint8Array(this._buffer);
		}

		/** @param {Uint8Array}|{Array} buffer */
		decode(_buffer) {
			this._buffer = Array.from(_buffer);
			this._index = 0;
			var _id=this.readVaruint();
			this.slot=this.readBigEndianShort();
			return this;
		}

		static fromBuffer(buffer) {
			return new Serverbound.HeldItemChange().decode(buffer);
		}

		/** @return {string} */
		toString() {
			return "HeldItemChange(slot: " + this.slot + ")";
		}

	},

	CreativeInventoryAction: class extends Buffer {

		static get ID(){ return 24; }

		static get CLIENTBOUND(){ return false; }
		static get SERVERBOUND(){ return true; }

		constructor(slot=0, clickedItem=null) {
			super();
			this.slot = slot;
			this.clickedItem = clickedItem;
		}

		/** @return {Uint8Array} */
		encode() {
			this._buffer = [];
			this.writeVaruint(24);
			this.writeBigEndianShort(this.slot);
			this.writeBytes(this.clickedItem.encode());
			return new Uint8Array(this._buffer);
		}

		/** @param {Uint8Array}|{Array} buffer */
		decode(_buffer) {
			this._buffer = Array.from(_buffer);
			this._index = 0;
			var _id=this.readVaruint();
			this.slot=this.readBigEndianShort();
			this.clickedItem=Types.Slot.fromBuffer(this._buffer); this._buffer=this.clickedItem._buffer;
			return this;
		}

		static fromBuffer(buffer) {
			return new Serverbound.CreativeInventoryAction().decode(buffer);
		}

		/** @return {string} */
		toString() {
			return "CreativeInventoryAction(slot: " + this.slot + ", clickedItem: " + this.clickedItem + ")";
		}

	},

	UpdateSign: class extends Buffer {

		static get ID(){ return 25; }

		static get CLIENTBOUND(){ return false; }
		static get SERVERBOUND(){ return true; }

		constructor(position=0, lines=[]) {
			super();
			this.position = position;
			this.lines = lines;
		}

		/** @return {Uint8Array} */
		encode() {
			this._buffer = [];
			this.writeVaruint(25);
			this.writeBigEndianLong(this.position);
			for(var dghpcy5saw5lcw in this.lines){ var dghpcy5saw5lc1tk=this.encodeString(this.lines[dghpcy5saw5lcw]); this.writeVaruint(dghpcy5saw5lc1tk.length); this.writeBytes(dghpcy5saw5lc1tk); }
			return new Uint8Array(this._buffer);
		}

		/** @param {Uint8Array}|{Array} buffer */
		decode(_buffer) {
			this._buffer = Array.from(_buffer);
			this._index = 0;
			var _id=this.readVaruint();
			this.position=this.readBigEndianLong();
			var bhroaxmubgluzxm=4; this.lines=[]; for(var dghpcy5saw5lcw in this.lines){ this.lines[dghpcy5saw5lcw]=this.decodeString(this.readBytes(this.readVaruint())); }
			return this;
		}

		static fromBuffer(buffer) {
			return new Serverbound.UpdateSign().decode(buffer);
		}

		/** @return {string} */
		toString() {
			return "UpdateSign(position: " + this.position + ", lines: " + this.lines + ")";
		}

	},

	Animation: class extends Buffer {

		static get ID(){ return 26; }

		static get CLIENTBOUND(){ return false; }
		static get SERVERBOUND(){ return true; }

		// hand
		static get MAIN_HAND(){ return 0; }
		static get OFF_HAND(){ return 1; }

		constructor(hand=0) {
			super();
			this.hand = hand;
		}

		/** @return {Uint8Array} */
		encode() {
			this._buffer = [];
			this.writeVaruint(26);
			this.writeVaruint(this.hand);
			return new Uint8Array(this._buffer);
		}

		/** @param {Uint8Array}|{Array} buffer */
		decode(_buffer) {
			this._buffer = Array.from(_buffer);
			this._index = 0;
			var _id=this.readVaruint();
			this.hand=this.readVaruint();
			return this;
		}

		static fromBuffer(buffer) {
			return new Serverbound.Animation().decode(buffer);
		}

		/** @return {string} */
		toString() {
			return "Animation(hand: " + this.hand + ")";
		}

	},

	Spectate: class extends Buffer {

		static get ID(){ return 27; }

		static get CLIENTBOUND(){ return false; }
		static get SERVERBOUND(){ return true; }

		constructor(player=new Uint8Array(16)) {
			super();
			this.player = player;
		}

		/** @return {Uint8Array} */
		encode() {
			this._buffer = [];
			this.writeVaruint(27);
			this.writeBytes(this.player);
			return new Uint8Array(this._buffer);
		}

		/** @param {Uint8Array}|{Array} buffer */
		decode(_buffer) {
			this._buffer = Array.from(_buffer);
			this._index = 0;
			var _id=this.readVaruint();
			this.player=this.readBytes(16);
			return this;
		}

		static fromBuffer(buffer) {
			return new Serverbound.Spectate().decode(buffer);
		}

		/** @return {string} */
		toString() {
			return "Spectate(player: " + this.player + ")";
		}

	},

	PlayerBlockPlacement: class extends Buffer {

		static get ID(){ return 28; }

		static get CLIENTBOUND(){ return false; }
		static get SERVERBOUND(){ return true; }

		// hand
		static get MAIN_HAND(){ return 0; }
		static get OFF_HAND(){ return 1; }

		constructor(position=0, face=0, hand=0, cursorPosition={x:0,y:0,z:0}) {
			super();
			this.position = position;
			this.face = face;
			this.hand = hand;
			this.cursorPosition = cursorPosition;
		}

		/** @return {Uint8Array} */
		encode() {
			this._buffer = [];
			this.writeVaruint(28);
			this.writeBigEndianLong(this.position);
			this.writeVaruint(this.face);
			this.writeVaruint(this.hand);
			this.writeBigEndianByte(this.cursorPosition.x); this.writeBigEndianByte(this.cursorPosition.y); this.writeBigEndianByte(this.cursorPosition.z);
			return new Uint8Array(this._buffer);
		}

		/** @param {Uint8Array}|{Array} buffer */
		decode(_buffer) {
			this._buffer = Array.from(_buffer);
			this._index = 0;
			var _id=this.readVaruint();
			this.position=this.readBigEndianLong();
			this.face=this.readVaruint();
			this.hand=this.readVaruint();
			this.cursorPosition={}; this.cursorPosition.x=this.readBigEndianByte(); this.cursorPosition.y=this.readBigEndianByte(); this.cursorPosition.z=this.readBigEndianByte();
			return this;
		}

		static fromBuffer(buffer) {
			return new Serverbound.PlayerBlockPlacement().decode(buffer);
		}

		/** @return {string} */
		toString() {
			return "PlayerBlockPlacement(position: " + this.position + ", face: " + this.face + ", hand: " + this.hand + ", cursorPosition: " + this.cursorPosition + ")";
		}

	},

	UseItem: class extends Buffer {

		static get ID(){ return 29; }

		static get CLIENTBOUND(){ return false; }
		static get SERVERBOUND(){ return true; }

		// hand
		static get MAIN_HAND(){ return 0; }
		static get OFF_HAND(){ return 1; }

		constructor(hand=0) {
			super();
			this.hand = hand;
		}

		/** @return {Uint8Array} */
		encode() {
			this._buffer = [];
			this.writeVaruint(29);
			this.writeVaruint(this.hand);
			return new Uint8Array(this._buffer);
		}

		/** @param {Uint8Array}|{Array} buffer */
		decode(_buffer) {
			this._buffer = Array.from(_buffer);
			this._index = 0;
			var _id=this.readVaruint();
			this.hand=this.readVaruint();
			return this;
		}

		static fromBuffer(buffer) {
			return new Serverbound.UseItem().decode(buffer);
		}

		/** @return {string} */
		toString() {
			return "UseItem(hand: " + this.hand + ")";
		}

	},

}

//export { Serverbound };
