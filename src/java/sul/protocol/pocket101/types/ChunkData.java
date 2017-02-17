/*
 * This file was automatically generated by sel-utils and
 * released under the GNU General Public License version 3.
 * 
 * License: https://github.com/sel-project/sel-utils/blob/master/LICENSE
 * Repository: https://github.com/sel-project/sel-utils
 * Generated from https://github.com/sel-project/sel-utils/blob/master/xml/protocol/pocket101.xml
 */
package sul.protocol.pocket101.types;

import java.util.Arrays;

import sul.utils.*;

/**
 * Chunk's blocks, lights and other immutable data.
 */
public class ChunkData extends Stream {

	/**
	 * 16x16x16 section of the chunk. The array's keys also indicate the section's height
	 * (the 3rd element of the array will be the 3rd section from bottom, starting at `y=24`).
	 * The amount of sections should be in a range from 0 (empty chunk) to 16.
	 */
	public sul.protocol.pocket101.types.Section[] sections = new sul.protocol.pocket101.types.Section[0];

	/**
	 * Coordinates of the highest block in the column that receives sky light (order `xz`).
	 */
	public short[] heights = new short[256];

	/**
	 * Biomes in order `xz`.
	 */
	public byte[] biomes = new byte[256];

	/**
	 * Colums where there are world borders (in format `xz`). This feature hasn't been
	 * implemented in the game yet and crashes the client.
	 */
	public byte[] borders = new byte[0];
	public sul.protocol.pocket101.types.ExtraData[] extraData = new sul.protocol.pocket101.types.ExtraData[0];

	/**
	 * Additional data for the chunk's block entities (tiles).
	 */
	public byte[] blockEntities;

	public ChunkData() {}

	public ChunkData(sul.protocol.pocket101.types.Section[] sections, short[] heights, byte[] biomes, byte[] borders, sul.protocol.pocket101.types.ExtraData[] extraData, byte[] blockEntities) {
		this.sections = sections;
		this.heights = heights;
		this.biomes = biomes;
		this.borders = borders;
		this.extraData = extraData;
		this.blockEntities = blockEntities;
	}

	@Override
	public int length() {
		int length=Buffer.varuintLength(sections.length) + Buffer.varuintLength(borders.length) + borders.length + Buffer.varuintLength(extraData.length) + blockEntities.length + 768; for(sul.protocol.pocket101.types.Section cvdlbm:sections){ length+=cvdlbm.length(); };for(sul.protocol.pocket101.types.ExtraData zhcfyr:extraData){ length+=zhcfyr.length(); } return length;
	}

	@Override
	public byte[] encode() {
		this._buffer = new byte[this.length()];
		this.writeVaruint((int)sections.length); for(sul.protocol.pocket101.types.Section cvdlbm:sections){ this.writeBytes(cvdlbm.encode()); }
		for(short avzhc:heights){ this.writeBigEndianShort(avzhc); }
		this.writeBytes(biomes);
		this.writeVaruint((int)borders.length); this.writeBytes(borders);
		this.writeVaruint((int)extraData.length); for(sul.protocol.pocket101.types.ExtraData zhcfyr:extraData){ this.writeBytes(zhcfyr.encode()); }
		this.writeBytes(blockEntities);
		byte[] _this = this.getBuffer();
		this._buffer = new byte[10 + _this.length];
		this.writeVaruint(_this.length);
		this.writeBytes(_this);
		return this.getBuffer();
	}

	@Override
	public void decode(byte[] buffer) {
		this._buffer = buffer;
		final int _length=this.readVaruint();
		final int _length_index = this._index;
		this._buffer = this.readBytes(_length);
		this._index = 0;
		int bnyrb5=this.readVaruint(); sections=new sul.protocol.pocket101.types.Section[bnyrb5]; for(int cvdlbm=0;cvdlbm<sections.length;cvdlbm++){ sections[cvdlbm]=new sul.protocol.pocket101.types.Section(); sections[cvdlbm]._index=this._index; sections[cvdlbm].decode(this._buffer); this._index=sections[cvdlbm]._index; }
		final int bhaddm=256; heights=new short[bhaddm]; for(int avzhc=0;avzhc<heights.length;avzhc++){ heights[avzhc]=readBigEndianShort(); }
		final int bjb1c=256; biomes=this.readBytes(bjb1c);
		int bjcrcm=this.readVaruint(); borders=this.readBytes(bjcrcm);
		int bvdjrfy=this.readVaruint(); extraData=new sul.protocol.pocket101.types.ExtraData[bvdjrfy]; for(int zhcfyr=0;zhcfyr<extraData.length;zhcfyr++){ extraData[zhcfyr]=new sul.protocol.pocket101.types.ExtraData(); extraData[zhcfyr]._index=this._index; extraData[zhcfyr].decode(this._buffer); this._index=extraData[zhcfyr]._index; }
		blockEntities=this.readBytes(this._buffer.length-this._index);
		this._index += _length_index;
	}

	@Override
	public String toString() {
		return "ChunkData(sections: " + Arrays.deepToString(this.sections) + ", heights: " + Arrays.toString(this.heights) + ", biomes: " + Arrays.toString(this.biomes) + ", borders: " + Arrays.toString(this.borders) + ", extraData: " + Arrays.deepToString(this.extraData) + ", blockEntities: " + Arrays.toString(this.blockEntities) + ")";
	}


}
