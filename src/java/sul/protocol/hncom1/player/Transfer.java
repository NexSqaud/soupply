/*
 * This file was automatically generated by sel-utils and
 * released under the GNU General Public License version 3.
 *
 * License: https://github.com/sel-project/sel-utils/blob/master/LICENSE
 * Repository: https://github.com/sel-project/sel-utils
 * Generated from https://github.com/sel-project/sel-utils/blob/master/xml/protocol/hncom1.xml
 */
package sul.protocol.hncom1.player;

import sul.utils.*;

/**
 * Transfers a player to another node. When a player is transferred from the node the
 * hub will not send the Remove packet and there's no way, for the node, to know whether
 * the player was disconnected or successfully transferred.
 */
public class Transfer extends Packet {

	public static final byte ID = (byte)17;

	public static final boolean CLIENTBOUND = false;
	public static final boolean SERVERBOUND = true;

	public int hubId;
	public int node;

	public Transfer() {}

	public Transfer(int hubId, int node) {
		this.hubId = hubId;
		this.node = node;
	}

	@Override
	public int length() {
		return Buffer.varuintLength(hubId) + Buffer.varuintLength(node) + 1;
	}

	@Override
	public byte[] encode() {
		this._buffer = new byte[this.length()];
		this.writeBigEndianByte(ID);
		this.writeVaruint(hubId);
		this.writeVaruint(node);
		return this.getBuffer();
	}

	@Override
	public void decode(byte[] buffer) {
		this._buffer = buffer;
		readBigEndianByte();
		hubId=this.readVaruint();
		node=this.readVaruint();
	}

	public static Transfer fromBuffer(byte[] buffer) {
		Transfer ret = new Transfer();
		ret.decode(buffer);
		return ret;
	}

}
