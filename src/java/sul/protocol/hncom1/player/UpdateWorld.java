/*
 * This file was automatically generated by sel-utils and
 * released under the GNU General Public License version 3.
 *
 * License: https://github.com/sel-project/sel-utils/blob/master/LICENSE
 * Repository: https://github.com/sel-project/sel-utils
 * Generated from https://github.com/sel-project/sel-utils/blob/master/xml/protocol/hncom1.xml
 */
package sul.protocol.hncom1.player;

import java.nio.charset.StandardCharsets;

import sul.utils.*;

public class UpdateWorld extends Packet {

	public static final byte ID = (byte)20;

	public static final boolean CLIENTBOUND = false;
	public static final boolean SERVERBOUND = true;

	public int hubId;
	public String world;
	public byte dimension;

	public UpdateWorld() {}

	public UpdateWorld(int hubId, String world, byte dimension) {
		this.hubId = hubId;
		this.world = world;
		this.dimension = dimension;
	}

	@Override
	public int length() {
		return Buffer.varuintLength(hubId) + Buffer.varuintLength(world.getBytes(StandardCharsets.UTF_8).length) + world.getBytes(StandardCharsets.UTF_8).length + 2;
	}

	@Override
	public byte[] encode() {
		this._buffer = new byte[this.length()];
		this.writeBigEndianByte(ID);
		this.writeVaruint(hubId);
		byte[] d29ybgq=world.getBytes(StandardCharsets.UTF_8); this.writeVaruint((int)d29ybgq.length); this.writeBytes(d29ybgq);
		this.writeBigEndianByte(dimension);
		return this.getBuffer();
	}

	@Override
	public void decode(byte[] buffer) {
		this._buffer = buffer;
		readBigEndianByte();
		hubId=this.readVaruint();
		int bgvud29ybgq=this.readVaruint(); world=new String(this.readBytes(bgvud29ybgq), StandardCharsets.UTF_8);
		dimension=readBigEndianByte();
	}

	public static UpdateWorld fromBuffer(byte[] buffer) {
		UpdateWorld ret = new UpdateWorld();
		ret.decode(buffer);
		return ret;
	}

}
