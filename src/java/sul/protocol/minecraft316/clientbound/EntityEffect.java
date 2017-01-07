/*
 * This file has been automatically generated by sel-utils and
 * released under the GNU General Public License version 3.
 *
 * License: https://github.com/sel-project/sel-utils/blob/master/LICENSE
 * Repository: https://github.com/sel-project/sel-utils
 * Generator: https://github.com/sel-project/sel-utils/blob/master/xml/protocol/minecraft316.xml
 */
package sul.protocol.minecraft316.clientbound;

import java.util.UUID;

import sul.protocol.minecraft316.types.*;
import sul.utils.*;

class EntityEffect extends Packet {

	public final static int ID = (int)71;

	public final static boolean CLIENTBOUND = true;
	public final static boolean SERVERBOUND = false;

	// flags
	public final static byte AMBIENT = (byte)1;
	public final static byte SHOW_PARTICLES = (byte)2;

	public int entityId;
	public byte effectId;
	public byte amplifier;
	public int duration;
	public byte flags;

	@Override
	public int length() {
		return Var.Uint.length(entityId) + Var.Uint.length(duration) + 3;
	}

	@Override
	public byte[] encode() {
	}

	@Override
	public void decode(byte[] buffer) {
	}

}
