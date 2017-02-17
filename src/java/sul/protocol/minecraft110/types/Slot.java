/*
 * This file was automatically generated by sel-utils and
 * released under the GNU General Public License version 3.
 * 
 * License: https://github.com/sel-project/sel-utils/blob/master/LICENSE
 * Repository: https://github.com/sel-project/sel-utils
 * Generated from https://github.com/sel-project/sel-utils/blob/master/xml/protocol/minecraft110.xml
 */
package sul.protocol.minecraft110.types;

import java.util.Arrays;

import sul.utils.*;

public class Slot extends Stream {

	public short id;
	public byte count;
	public short damage;
	public byte[] nbt = new byte[0];

	public Slot() {}

	public Slot(short id, byte count, short damage, byte[] nbt) {
		this.id = id;
		this.count = count;
		this.damage = damage;
		this.nbt = nbt;
	}

	@Override
	public int length() {
		return nbt.length + 5;
	}

	@Override
	public byte[] encode() {
		this._buffer = new byte[this.length()];
		this.writeBigEndianShort(id);
		if(id>0){ this.writeBigEndianByte(count); }
		if(id>0){ this.writeBigEndianShort(damage); }
		if(id>0){ this.writeBytes(nbt); }
		return this.getBuffer();
	}

	@Override
	public void decode(byte[] buffer) {
		this._buffer = buffer;
		id=readBigEndianShort();
		if(id>0){ count=readBigEndianByte(); }
		if(id>0){ damage=readBigEndianShort(); }
		if(id>0){ nbt=this.readBytes(this._buffer.length-this._index); }
	}

	@Override
	public String toString() {
		return "Slot(id: " + this.id + ", count: " + this.count + ", damage: " + this.damage + ", nbt: " + Arrays.toString(this.nbt) + ")";
	}


}
