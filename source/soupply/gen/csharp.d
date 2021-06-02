module soupply.gen.csharp;

import std.algorithm : sort, canFind, min, max, reverse, count;
import std.array : replicate;
import std.ascii : newline;
import std.conv : to;
import std.file : mkdir, mkdirRecurse, exists;
import std.json;
import std.math : isNaN;
import std.path : dirSeparator;
import std.regex : ctRegex, replaceAll, matchFirst;
import std.string;
import std.typecons : tuple;
import std.typetuple : TypeTuple;

import soupply.data;
import soupply.generator;
import soupply.gen.code;
import soupply.util;

import transforms : snakeCase, camelCaseLower, camelCaseUpper;

class CSharpGenerator : CodeGenerator {

	static this() {
		Generator.register!CSharpGenerator("CSharp", "csharp", "");//"src/" ~ SOFTWARE, ["/*", "*", "*/"]);
	}

	public this()
	{
		CodeMaker.Settings settings;
		settings.inlineBraces = false;
		settings.moduleSeparator = ".";
		settings.standardLibrary = "System";

		settings.moduleStat = "namespace %s";
		settings.importStat = "using %s";
		settings.classStat = "class %s";
		settings.constStat = "enum %s = %d";

		super(settings, "cs");

	}

	import std.stdio : writeln;

	protected override void generateImpl(Data d) {
		super.generateImpl(d);
		
		auto software = camelCaseUpper(SOFTWARE);

		foreach(game, info; d.info) {
			game = camelCaseUpper(game);
			if(info.latest) {
				// read files from {game}/src/main/java/{game} and copy to {info.game}/src/main/java/{info.game}
				import std.file;
				foreach(string dir ; dirEntries("gen/csharp/" ~ game, SpanMode.breadth)) {
					if(dir.isDir) mkdirRecurse(dir.replace(game, info.game));
				}
				foreach(string file ; dirEntries("gen/csharp/" ~ game, SpanMode.breadth)) {
					if(file.isFile) std.file.write(file.replace(game, info.game), replace(cast(string)read(file), game, info.game));
					//if(file.isFile) std.file.write(file.replace(game, info.game), read(file));
				}
			}
		}

		string[] tuples;
		void add(string type) {
			immutable open = type.indexOf("<");
			if(open != -1) {
				immutable tuple = this.convertType("", type[0..open]) ~ "." ~ type[open+1..type.indexOf(">")];
				if(!tuples.canFind(tuple)) tuples ~= tuple;
			}
		}
		void fields(Protocol.Field[] fields) {
			foreach(field ; fields) add(field.type);
		}
		foreach(info ; d.info) {
			foreach(type ; info.protocol.types) fields(type.fields);
			foreach(section ; info.protocol.sections) {
				foreach(packet ; section.packets) {
					fields(packet.fields);
					foreach(variant ; packet.variants) fields(variant.fields);
				}
			}
		}

		foreach(tuple ; tuples) {
			immutable p = tuple.indexOf(".");
			immutable type = convertType("", tuple[0..p]);
			immutable coords = tuple[p+1..$];
			immutable name = capitalize(tuple[0..p]) ~ toUpper(coords);
			with(make("Utils/", "", "", name)) {
				clear();
				block("namespace " ~ software ~ ".Utils");
				block("public class " ~ name).nl;
				// fields
				string[] ctor;
				foreach(coord ; coords) {
					stat("public " ~ type ~ " " ~ pascalCase(to!string(coord)));
					ctor ~= (type ~ " " ~ coord);
				}
				nl();
				// empty ctor
				line("public " ~ name ~ "() {}").nl;
				// ctor
				block("public " ~ name ~ "(" ~ ctor.join(", ") ~ ")");
				foreach(coord ; coords) {
					stat("" ~ pascalCase(to!string(coord)) ~ " = " ~ coord);
				}
				endBlock().nl;
				endBlock();
				endBlock();
				save();
			}
		}
	}

	protected override void generateGame(string game, Info info) {
		auto software = camelCaseUpper(SOFTWARE);
		game = camelCaseUpper(game);
		super.game = game;
		this.game = game;
		void writeFields(CodeMaker source, string className, Protocol.Field[] fields) {
			// constants
			foreach(field ; fields) {
				if(field.constants.length) {
					source.line("// " ~ field.name.replace("_", " "));
					foreach(constant ; field.constants) {
						source.stat("public const " ~ source.convertType(field.type) ~ " " ~ toUpper(constant.name) ~ " = " ~ (field.type == "string" ? JSONValue(constant.value).toString() : "(" ~ source.convertType(field.type) ~ ")" ~ constant.value));
					}
					source.nl;
				}
			}
			// fields
			foreach(i, field; fields) {
				if(camelCaseUpper(field.name) == className)
					field.name = field.name ~ "s";
				source.stat("public " ~ source.convertType(field.type) ~ " " ~ (field.name == "?" ? "Unknown" ~ to!string(i) : convertName(field.name, true)) ~ (field.default_.length ? " = " ~ constOf(field.default_) : ""));
				if(i == fields.length - 1) source.nl;
			}
			// constructors
			if(fields.length) {
				source.block("public " ~ className ~ "()");
				// init static arrays and classes
				foreach(i, field; fields) {
					immutable name = field.name == "?" ? "Unknown" ~ to!string(i) : convertName(field.name, true);
					immutable conv = source.convertType(field.type);
					// static arrays
					immutable aopen = field.type.indexOf("[");
					immutable aclose = field.type.indexOf("]");
					if(aopen != -1 && aclose > aopen + 1) {
						source.stat("this." ~ name ~ " = new " ~ conv.replace("[]", field.type[aopen..aclose+1]));
					} else if(aopen == -1) {
						if(field.type.indexOf("<") != -1 || conv.startsWith(software ~ ".") || field.type == "metadata") {
							source.stat("" ~ name ~ " = new " ~ conv ~ "()");
						} else if(field.type == "uuid") {
							source.stat("" ~ name ~ " = new Uuid(0, 0)");
						}
					}
				}
				source.endBlock().nl;
				string[] args;
				foreach(i, field; fields) {
					immutable type = source.convertType(field.type);
					immutable p = type.canFind('[');
					args ~= type ~ " " ~ (field.name == "?" ? "unknown" ~ to!string(i) : convertName(field.name));
				}
				source.block("public " ~ className ~ "(" ~ args.join(", ") ~ ")");
				foreach(i, field; fields) {
					immutable name = field.name == "?" ? "unknown" ~ to!string(i) : convertName(field.name);
					source.stat("" ~ pascalCase(name.indexOf("@") == 0 ? name[1..$] : name) ~ (camelCaseUpper(field.name) == className ? "s" : "") ~ " = " ~ name);
				}
				source.endBlock().nl;
			}
		}

		string endiannessOf(string type, string over="") {
			auto res = over.length ? camelCaseUpper(over) : camelCaseUpper(info.protocol.endianness);
			res = res.replace("uint", "UInt32")
				.replace("ulong", "UInt64")
				.replace("int", "Int32")
				.replace("long", "Int64")
				.replace("float", "Single");
			return res;
		}

		string transformName(string name)
		{
			return capitalize(name)
				.replace("Int", "Int32")
				.replace("Short", "Int16")
				.replace("Float", "Single")
				.replace("Long", "Int64")
				.replace("Ushort", "UInt16")
				.replace("Uint", "UInt32")
				.replace("Ulong", "UInt64")
				.replace("Bool", "Boolean")
				.replace("short", "Int16")
				.replace("ushort", "UInt16")
				.replace("uint", "UInt32")
				.replace("ulong", "UInt64")
				.replace("int", "Int32")
				.replace("long", "Int64")
				.replace("float", "Single")
				.replace("bool", "Boolean");
		}

		void createEncoding(CodeMaker source, string type, string name, string e="", string arrayLength="", string lengthEndianness="", bool camelUpperCasing = true) {
			//if(type[0] == 'u' && defaultTypes.canFind(type[1..$])) type = type[1..$];
			if(type == "ubyte") type = "byte";
			auto lo = type.lastIndexOf("[");
			if(lo > 0) {
				auto lc = type.lastIndexOf("]");
				immutable nt = type[0..lo];
				immutable cnt = source.convertType(nt);
				if(lo == lc - 1) {
					// dynamic array, has length
					if(arrayLength.length) {
						// custom length
						createEncoding(source, arrayLength, "(" ~ source.convertType(arrayLength) ~ ")" ~ name ~ ".Length", lengthEndianness, "", "" , false);
					} else {
						// default length
						createEncoding(source, info.protocol.arrayLength, "(" ~ source.convertType(info.protocol.arrayLength) ~ ")" ~ name ~ ".Length", "", "", "" , false);
					}
				}
				if(cnt == "byte") source.stat("buffer.WriteBytes(" ~ name ~ ")");
				else {
					source.block("foreach(var " ~ hash(name) ~ " in " ~ name ~ ")");
					createEncoding(source, nt, hash(name), "", "", "", false);
					source.endBlock();
				}
			} else {
				auto ts = type.lastIndexOf("<");
				if(ts > 0) {
					auto te = type.lastIndexOf(">");
					string nt = type[0..ts];
					string[] ret;
					foreach(i ; type[ts+1..te]) {
						createEncoding(source, nt, name ~ "." ~ pascalCase(to!string(i)), "", "", "", camelUpperCasing);
					}
				} else {
					if(type.startsWith("var")) source.stat("buffer.Write" ~ transformName(type) ~ "(" ~ (camelUpperCasing ? convertName(name, true) : name)  ~ ")");
					else if(type == "string"){ source.stat("byte[] " ~ hash(name) ~ " = Encoding.UTF8.GetBytes(" ~ (camelUpperCasing ? convertName(name, true) : name) ~ ")"); createEncoding(source, "byte[]", hash(name)); }
					else if(type == "uuid") source.stat("buffer.WriteUuid(" ~ (camelUpperCasing ? convertName(name, true) : name) ~ ")");
					else if(type == "bytes") source.stat("buffer.WriteBytes(" ~ (camelUpperCasing ? convertName(name, true) : name) ~ ")");
					else if(type == "bool" || type == "byte") source.stat("buffer.Write" ~ transformName(type) ~ "(" ~ (camelUpperCasing ? convertName(name, true) : name) ~ ")");
					else if(defaultTypes.canFind(type)) source.stat("buffer.Write" ~ endiannessOf(type, e) ~ transformName(type) ~ "(" ~ (camelUpperCasing ? convertName(name, true) : name) ~ ")");
					else source.stat((camelUpperCasing ? convertName(name, true) : name) ~ ".EncodeBody(buffer)");
				}
			}
		}

		void createEncodings(CodeMaker source, Protocol.Field[] fields, string className = "") {
			string nextc = "";
			foreach(i, field; fields) {
				if(field.condition.length && field.condition != nextc)
				{
					auto conditionSplit = field.condition.split("||");
					auto condition = "";
					foreach(cond ; conditionSplit)
					{
						auto conditionSplit2 = cond.split("&");
						auto condition2 = "";
						foreach(cond2 ; conditionSplit2)
							condition2 = condition2 ~ pascalCase(cond2, false) ~ (cond2 != conditionSplit2[conditionSplit2.length - 1] ? "&" : "");
						condition = condition ~ pascalCase(condition2) ~ (cond != conditionSplit[conditionSplit.length - 1] ? "||" : "");
					}
					source.block("if(" ~ condition ~ ")");
				}
				if(camelCaseUpper(field.name) == className)
					field.name = field.name ~ "s";
				createEncoding(source, field.type, field.name=="?" ? "Unknown" ~ i.to!string : convertName(field.name, true), field.endianness, field.length, field.lengthEndianness);
				if(field.condition.length && (i >= fields.length - 1 || fields[i+1].condition != field.condition)) source.endBlock();
				nextc = field.condition;
			}
		}

		void createDecoding(CodeMaker source, string type, string name, string e="", string arrayLength="", string lengthEndianness="", bool camelUpperCasing = true) {
			//if(type[0] == 'u' && defaultTypes.canFind(type[1..$])) type = type[1..$];
			if(type == "ubyte") type = "byte";
			auto lo = type.lastIndexOf("[");
			if(lo > 0) {
				auto lc = type.lastIndexOf("]");
				immutable nt = type[0..lo];
				immutable cnt = source.convertType(nt);
				if(lo == lc - 1) {
					if(arrayLength.length) {
						createDecoding(source, arrayLength, arrayLength.toLower() ~ " " ~ hash("l" ~ name), lengthEndianness, "", "", false);
					} else {
						createDecoding(source, info.protocol.arrayLength, "uint " ~ hash("l" ~ name), "", "", "", false);
					}
				}
				if(cnt == "byte") {
					source.stat(name ~ " = buffer.ReadBytes(" ~ (lo == lc - 1 ? hash("l" ~ name) : name ~ ".Length") ~ ")");
				} else {
					if(lo == lc - 1) source.stat(name ~ " = new " ~ (cnt.indexOf("[") >= 0 ? (cnt[0..cnt.indexOf("[")] ~ "[" ~ hash("l" ~ name) ~ "][]") : (cnt ~ "[" ~ hash("l" ~ name) ~ "]")));
					source.block("for(int " ~ hash(name) ~ " = 0; " ~ hash(name) ~ " < " ~ name ~ ".Length; " ~ hash(name) ~ "++)");
					createDecoding(source, nt, name ~ "[" ~ hash(name) ~ "]", "", "", "", false);
					source.endBlock();
				}
			} else {
				auto ts = type.lastIndexOf("<");
				if(ts > 0) {
					auto te = type.lastIndexOf(">");
					string nt = type[0..ts];
					string[] ret;
					foreach(i ; type[ts+1..te]) {
						createDecoding(source, nt, name ~ "." ~ pascalCase(to!string(i)), "", "", "", camelUpperCasing);
					}
				} else {
					if(type.startsWith("var")) source.stat((camelUpperCasing ? convertName(name, true) : name) ~ " = buffer.Read" ~ transformName(type) ~ "()");
					else if(type == "string"){ createDecoding(source, info.protocol.arrayLength, "uint " ~ hash("len" ~ name), "", "", "", false); source.stat(convertName(name, true) ~ " = buffer.ReadString(" ~ hash("len" ~ name) ~ ")"); }
					else if(type == "uuid") source.stat((camelUpperCasing ? convertName(name, true) : name) ~ " = buffer.ReadUuid()");
					else if(type == "bytes") source.stat((camelUpperCasing ? convertName(name, true) : name) ~ " = buffer.ReadBytes(buffer.ByteBuffer.Length - buffer.Index)");
					else if(type == "bool" || type == "byte") source.stat((camelUpperCasing ? convertName(name, true) : name) ~ " = buffer.Read" ~ transformName(type) ~ "()");
					else if(defaultTypes.canFind(type)) source.stat((camelUpperCasing ? convertName(name, true) : name) ~ " = buffer.Read" ~ endiannessOf(type, e) ~ transformName(type) ~ "()");
					else source.stat((camelUpperCasing ? convertName(name, true) : name) ~ ".DecodeBody(buffer)");
				}
			}
		}

		void createDecodings(CodeMaker source, Protocol.Field[] fields, string className = "") {
			string nextc = "";
			foreach(i, field; fields) {
				if(field.condition.length && field.condition != nextc)
				{
					auto conditionSplit = field.condition.split("||");
					auto condition = "";
					foreach(cond ; conditionSplit)
					{
						auto conditionSplit2 = cond.split("&");
						auto condition2 = "";
						foreach(cond2 ; conditionSplit2)
							condition2 = condition2 ~ pascalCase(cond2, false) ~ (cond2 != conditionSplit2[conditionSplit2.length - 1] ? "&" : "");
						condition = condition ~ pascalCase(condition2) ~ (cond != conditionSplit[conditionSplit.length - 1] ? "||" : "");
					}
					//if(condition == field.condition)
					//{
					//	conditionSplit = field.condition.split("&");
					//	condition = "";
					//	foreach(cond ; conditionSplit)
					//		condition = condition ~ pascalCase(cond, false) ~ (cond != conditionSplit[conditionSplit.length - 1] ? "&" : "");
					//}
					source.block("if(" ~ condition ~ ")");
				}
				if(camelCaseUpper(field.name) == className)
					field.name = field.name ~ "s";
				createDecoding(source, field.type, field.name=="?" ? "Unknown" ~ i.to!string : convertName(field.name, true), field.endianness, field.length, field.lengthEndianness);
				if(field.condition.length && (i >= fields.length - 1 || fields[i+1].condition != field.condition)) source.endBlock();
				nextc = field.condition;
			}
		}


		auto pk = make(game, "", "", "", "Packet");
		with(pk) {
			clear(); // remove pre-generated package declaration
			stat("using System.Text");
			stat("using " ~ software ~ ".Objects");
			stat("using " ~ software ~ ".Exceptions");
			stat("using " ~ software ~ ".Utils");
			nl();
			block("namespace " ~ software ~ "." ~ game);
			block("public abstract class Packet : " ~ software ~ ".Abstractions.Packet");
			line("public static " ~ convertType(info.protocol.id) ~ " PacketId { get; set; }").nl;

			// encode
			// line("@Override");
			block("public override byte[] Encode()");
			stat("Buffer buffer = new Buffer()");
			createEncoding(pk, info.protocol.id, "PacketId", "", "", "", false);
			if(info.protocol.padding) stat("buffer.WriteBytes(new byte[" ~ info.protocol.padding.to!string ~ "])");
			stat("EncodeBody(buffer)");
			stat("return buffer.ToByteArray()");
			endBlock().nl;

			// decode
			// line("@Override");
			block("public override void Decode(byte[] data)");
			stat("Buffer buffer = new Buffer(data)");
			createDecoding(pk, info.protocol.id, "PacketId", "", "", "", false);
			if(info.protocol.padding) stat("buffer.ReadBytes(" ~ info.protocol.padding.to!string ~ ")");
			stat("DecodeBody(buffer)");
			endBlock().nl;
			endBlock();
			endBlock();
			save();

		}
		foreach(type ; info.protocol.types) {
			immutable clength = type.length.length != 0;
			auto t = make(game, "", "", "", "Types", camelCaseUpper(type.name));
			with(t) {
				clear();
				stat("using System.Text");
				stat("using " ~ software ~ ".Abstractions");
				stat("using " ~ software ~ ".Exceptions");
				stat("using " ~ software ~ ".Objects");
				stat("using " ~ software ~ ".Utils");
				nl;
				block("namespace " ~ software ~ "." ~ game ~ ".Types");
				block("public class " ~ camelCaseUpper(type.name) ~ " : Type");
				// fields
				writeFields(t, camelCaseUpper(type.name), type.fields);
				// encode
				// line("@Override");
				block("public override void EncodeBody(Buffer buffer)");
				if(clength) {
					stat("Buffer nBuffer = new Buffer()");
					stat("EncodeBodyImpl(nBuffer)");
					createEncoding(t, type.length, "(uint)nBuffer.ByteBuffer.Length", "", "", "", false);
					stat("buffer.WriteBytes(nBuffer.ToByteArray())");
					endBlock().nl;
					block("private void EncodeBodyImpl(Buffer buffer)");
				}
				createEncodings(t, type.fields, camelCaseUpper(type.name));
				endBlock().nl;
				// decode
				// line("@Override");
				block("public override void DecodeBody(Buffer buffer)");
				if(clength) {
					createDecoding(t, type.length, "uint length", "", "", "", false);
					stat("DecodeBodyImpl(new Buffer(buffer.ReadBytes(length)))");
					endBlock().nl;
					block("private void DecodeBodyImpl(Buffer buffer)");
				}
				createDecodings(t, type.fields, camelCaseUpper(type.name));
				endBlock().nl;
				endBlock();
				endBlock();
				save();
			}
		}

		foreach(section ; info.protocol.sections) {
			foreach(packet ; section.packets) {
				auto p = make(game, "", "", "", "Protocol", camelCaseUpper(section.name), camelCaseUpper(packet.name));
				with(p) {
					clear();
					stat("using System.Text");
					stat("using " ~ software ~ ".Abstractions");
					stat("using " ~ software ~ ".Exceptions");
					stat("using " ~ software ~ ".Objects");
					stat("using " ~ software ~ ".Utils");
					nl();
					block("namespace " ~ software ~ "." ~ game ~ ".Protocol." ~ camelCaseUpper(section.name));
					block("public class " ~ camelCaseUpper(packet.name) ~ " : " ~ "Packet");
					stat("public static new " ~ convertType(info.protocol.id) ~ " PacketId { get; set; } = " ~ packet.id.to!string).nl;
					// fields
					writeFields(p, camelCaseUpper(packet.name), packet.fields);
					// id
					// line("@Override");
					// block("public override " ~ convertType(info.protocol.id) ~ " GetId()");
					// stat("return Id");
					// endBlock().nl;
					// encode
					// line("@Override");
					block("public override void EncodeBody(Buffer buffer)");
					createEncodings(p, packet.fields, camelCaseUpper(packet.name));
					endBlock().nl;
					// decode
					// line("@Override");
					block("public override void DecodeBody(Buffer buffer)");
					createDecodings(p, packet.fields, camelCaseUpper(packet.name));
					endBlock().nl;
					// static decode
					block("public static " ~ camelCaseUpper(packet.name) ~ " FromBuffer(byte[] buffer)");
					stat(camelCaseUpper(packet.name) ~ " packet = new " ~ camelCaseUpper(packet.name) ~ "()");
					stat("packet.TryDecode(buffer)");
					stat("return packet");
					endBlock().nl;
					if(packet.variantField.length) {
						block("private void EncodeMainBody(Buffer buffer)");
						stat("EncodeBody(buffer)");
						endBlock().nl;
						// variants
						foreach(variant ; packet.variants) {
							block("public class " ~ camelCaseUpper(variant.name) ~ " : " ~ camelCaseUpper(packet.name)).nl;
							writeFields(p, camelCaseUpper(variant.name), variant.fields);
							// encode
							//line("@Override");
							block("public override void EncodeBody(Buffer buffer)");
							stat(this.convertName(packet.variantField, true) ~ " = " ~ variant.value);
							stat("EncodeMainBody(buffer)");
							createEncodings(p, variant.fields);
							endBlock().nl;
							// decode
							// line("@Override");
							block("public override void DecodeBody(Buffer buffer)");
							createDecodings(p, variant.fields);
							endBlock().nl;
							endBlock().nl;
						}
					}
					endBlock();
					endBlock();
					save();
				}
			}
		}

		auto m = make(game, "", "", "", "Metadata/MetadataValue");
		immutable id = m.convertType(info.metadata.id);
		immutable ty = m.convertType(info.metadata.type);
		with(m) {
			clear();
			stat("using System.Text");
			stat("using " ~ software ~ ".Abstractions");
			stat("using " ~ software ~ ".Exceptions");
			stat("using " ~ software ~ ".Objects");
			stat("using " ~ software ~ ".Utils");
			nl();
			block("namespace " ~ software ~ "." ~ game ~ ".Metadata");
			block("public abstract class MetadataValue");
			stat("public " ~ id ~ " Id");
			stat("private " ~ ty ~ " Type").nl;
			// ctor
			block("public MetadataValue(" ~ id ~ " id, " ~ ty ~ " type)");
			stat("Id = id");
			stat("Type = type");
			endBlock().nl;
			// encode
			block("public virtual void EncodeBody(Buffer buffer)");
			createEncoding(m, info.metadata.id, "id");
			createEncoding(m, info.metadata.type, "type");
			endBlock().nl;
			// decode
			stat("public abstract void DecodeBody(Buffer buffer)");
			endBlock();
			endBlock();
			save();
		}

		foreach(type ; info.metadata.types) {
			immutable name = camelCaseUpper(type.name);
			auto tt = make(game, "", "", "", "Metadata/Metadata" ~ name);
			with(tt) {
				immutable conv = convertType(type.type);
				clear();
				stat("using System.Text");
				stat("using " ~ software ~ ".Abstractions");
				stat("using " ~ software ~ ".Exceptions");
				stat("using " ~ software ~ ".Objects");
				stat("using " ~ software ~ ".Utils");
				nl();
				block("namespace " ~ software ~ "." ~ game ~ ".Metadata");
				block("public class Metadata" ~ name ~ " : MetadataValue");
				stat("public " ~ conv ~ " Value").nl;
				// ctor
				block("public Metadata" ~ name ~ "(" ~ id ~ " id, " ~ convertType(type.type) ~ " value) : base(id, (" ~ ty ~ ")" ~ type.id.to!string ~ ")");
				//stat("super(id, (" ~ ty ~ ")" ~ type.id.to!string ~ ")");
				stat("Value = value");
				endBlock().nl;
				line("public Metadata" ~ name ~ "(" ~ id ~ " id) : ");
				if(type.type.indexOf("<") != -1 || conv.indexOf(".") != -1) line("this(id, new " ~ convertType(type.type) ~ "())");
				else if(conv.indexOf("[") != -1) line("this(id, new " ~ conv ~ "{})");
				else if(type.type == "bool") line("this(id, false)");
				else if(type.type == "string") line("this(id, \"\")");
				else line("this(id, (" ~ /*convertType(type.type)*/ conv ~ ")0)");
				line("{}").nl;
				// encode
				//line("@Override");
				block("public override void EncodeBody(Buffer buffer)");
				stat("base.EncodeBody(buffer)");
				createEncoding(tt, type.type, "Value", type.endianness);
				endBlock().nl;
				// decode
				// line("@Override");
				block("public override void DecodeBody(Buffer buffer)");
				createDecoding(tt, type.type, "Value", type.endianness);
				endBlock().nl;
				endBlock();
				endBlock();
				save();
			}
		}
		
		string[string] typetable;
		foreach(type ; info.metadata.types) {
			typetable[type.name] = type.type;
		}

		auto mm = make(game, "", "", "", "Metadata/Metadata");
		with(mm) {
			clear();
			stat("using System.Text");
			stat("using System.Collections.Generic");
			stat("using " ~ software ~ ".Abstractions");
			stat("using " ~ software ~ ".Exceptions");
			stat("using " ~ software ~ ".Objects");
			stat("using " ~ software ~ ".Utils");
			nl();
			stat("using Buffer = Soupply.Objects.Buffer");
			nl();
			block("namespace " ~ software ~ "." ~ game ~ ".Metadata");
			block("public class Metadata : Dictionary<" ~ (ty=="int" ? "int" : ( ty == "byte" ? "byte" : ( ty == "uint" ? "uint" :capitalize(ty)))) ~ ", MetadataValue>");
			// ctor
			block("public Metadata()");
			foreach(d ; info.metadata.data) {
				if(d.required) {
					immutable td = convertType(typetable[d.type]);
					stat("Add(new Metadata" ~ camelCaseUpper(d.type) ~ "((" ~ ty ~ ")" ~ d.id.to!string ~ ", " ~ (d.default_.length ?
																													   "(" ~ td ~ ")" ~ d.default_ :
																													   (defaultTypes[0..$-2].canFind(td) ? "(" ~ td ~ ")0" : (td == "String" ? `""` : "new " ~ td ~ "()"))) ~ "))");
				}
			}
			endBlock().nl;
			// add
			block("public void Add(MetadataValue value)");
			stat("Add(value.Id, value)");
			endBlock().nl;
			// encode
			block("public void EncodeBody(Buffer buffer)");
			if(info.metadata.length.length) createEncoding(mm, info.metadata.length, "(uint)Count");
			block("foreach (var value in Values)");
			stat("value.EncodeBody(buffer)");
			endBlock();
			if(info.metadata.suffix.length) createEncoding(mm, info.metadata.id, "(" ~ id ~ ")" ~ info.metadata.suffix);
			endBlock().nl;
			// decode
			block("public void DecodeBody(Buffer buffer)");
			if(info.metadata.length.length) {
				createDecoding(mm, info.metadata.length, convertType(info.metadata.length) ~ " length", "", "", "", false);
				block("while(length-- > 0)");
				createDecoding(mm, info.metadata.id, " " ~ id ~ " id");
			} else {
				// suffix
				block("while(true)");
				createDecoding(mm, info.metadata.id, " " ~ id ~ " id");
				stat("if(id == " ~ info.metadata.suffix ~ ") break");
			}
			createDecoding(mm, info.metadata.type, " " ~ ty ~ " type");
			stat("var value = GetMetadataValue(id, type)");
			stat("value.DecodeBody(buffer)");
			stat("Add(value)");
			endBlock();
			endBlock().nl;
			block("public static MetadataValue GetMetadataValue(" ~ id ~ " id, " ~ ty ~ " type)");
			block("switch(type)");
			foreach(type ; info.metadata.types) stat("case " ~ type.id.to!string ~ ": return new Metadata" ~ camelCaseUpper(type.name) ~ "(id)");
			stat("default: throw new MetadataException(id, type)");
			endBlock();
			endBlock().nl;
			// getters and setters
			foreach(d ; info.metadata.data) {
				immutable tp = convertType(typetable[d.type]);
				// getter
				block("public " ~ tp ~ " " ~ camelCaseUpper(d.name));
				block("get");
				stat("var value = this[" ~ d.id.to!string ~ "]");
				stat("if(value != null && value is Metadata" ~ camelCaseUpper(d.type) ~ " b) return b.Value");
				if(d.default_.length) stat("else return (" ~ tp ~ ")" ~ d.default_);
				else if(tp == "bool") stat("else return false");
				else if(tp == "string") stat("else return \"\"");
				else if(defaultTypes.canFind(tp)) stat("else return 0");
				else stat("else return null");
				endBlock().nl;
				// setter
				block("set");
				stat("var a = this[" ~ d.id.to!string ~ "]");
				stat("if(a != null && a is Metadata" ~ camelCaseUpper(d.type) ~ " b) b.Value = value");
				stat("else Add(new Metadata" ~ camelCaseUpper(d.type) ~ "((" ~ ty ~ ")" ~ d.id.to!string ~ ", value))");
				endBlock().nl;
				endBlock().nl;
			}
			endBlock();
			endBlock();
			save();
		}

	}

	enum keywords = ["default", "internal"];

	protected override string convertName(string name) {
		return convertName(name, false);
	}

	protected string convertName(string name, bool toPascalCase) {
		if(keywords.canFind(name) && !toPascalCase)
			name = "@" ~ name;
		return toPascalCase ? pascalCase(name) : name.camelCaseLower;
	}
	
	private string pascalCase(string str, bool ignoreBrackets = true)
	{
		bool addAt = str[0] == '@';
		bool addBracket = str[0] == '(' && !ignoreBrackets;
		if(addAt || addBracket) str = str[1..$];
		auto pieces = str.split("_");
		auto res = "";
		foreach(piece ; pieces)
			res = res ~ to!string(piece[0].toUpper()) ~ piece[1..$];
		return (addAt ? "@" : (addBracket ? "(" : "")) ~ res;
	}

	// type conversion

	enum defaultTypes = ["bool", "byte", "short", "ushort", "int", "uint", "long", "ulong", "float", "double", "string", "Uuid"];

	enum string[string] defaultAliases = [
		//"bool": "bool",
		"ubyte": "byte",
		//"ushort": "short",
		//"uint": "int",
		//"ulong": "long",
		//"string": "string",
		"uuid": "Uuid",
		"bytes": "byte[]",
		"varshort": "short",
		"varushort": "ushort",
		"varint": "int",
		"varuint": "uint",
		"varlong": "long",
		"varulong": "ulong"
	];

	protected override string convertType(string game, string type) {
		auto end = min(cast(size_t)type.indexOf("["), cast(size_t)type.lastIndexOf("<"), type.length);
		auto t = type[0..end];
		auto e = type[end..$].replaceAll(ctRegex!`\[[0-9]{1,}\]`, "[]");
		auto a = t in defaultAliases;
		if(a) return convertType(game, *a ~ e);
		if(e.length && e[0] == '<') return toPascalCase(t) ~ toUpper(e[1..e.indexOf(">")]) ~ e[e.indexOf(">")+1..$];
		else if(defaultTypes.canFind(t)) return t ~ e;
		else if(t == "metadata") return "Metadata.Metadata";
		else return "Types." ~ toPascalCase(t) ~ e;
	}

}
