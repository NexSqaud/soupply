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

class Title extends Packet {

	public final static int ID = (int)69;

	public final static boolean CLIENTBOUND = true;
	public final static boolean SERVERBOUND = false;

	public int action;

	@Override
	public int length() {
		return Var.Uint.length(action);
	}

	@Override
	public byte[] encode() {
	}

	@Override
	public void decode(byte[] buffer) {
	}

	public static class SetTitle extends Title {

	}

	public static class SetSubtitle extends Title {

	}

	public static class SetActionBar extends Title {

	}

	public static class SetTimings extends Title {

	}

	public static class Hide extends Title {

	}

	public static class Reset extends Title {

	}

}
