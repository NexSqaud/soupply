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

class Statistics extends Packet {

	public final static int ID = (int)7;

	public final static boolean CLIENTBOUND = true;
	public final static boolean SERVERBOUND = false;

	public Statistic[] statistics;

	@Override
	public int length() {
		return Var.Uint.length(statistics.length) + statistics.length();
	}

	@Override
	public byte[] encode() {
	}

	@Override
	public void decode(byte[] buffer) {
	}

}
