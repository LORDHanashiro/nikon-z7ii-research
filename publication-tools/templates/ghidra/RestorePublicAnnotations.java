import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.symbol.SourceType;
import com.google.gson.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

/** Independently authored metadata importer; no firmware byte edits or code creation. */
public class RestorePublicAnnotations extends GhidraScript {
    long number(String s) { return Long.decode(s); }
    DataType resolve(String kind, int size, Map<String,StructureDataType> types) {
        if (kind.equals("u8")) return ByteDataType.dataType;
        if (kind.equals("u16")) return WordDataType.dataType;
        if (kind.equals("u32")) return DWordDataType.dataType;
        if (kind.equals("ptr")) return new Pointer32DataType();
        if (kind.startsWith("ptr:") && types.containsKey(kind.substring(4))) return new Pointer32DataType(types.get(kind.substring(4)));
        if (kind.startsWith("struct:") && types.containsKey(kind.substring(7))) return types.get(kind.substring(7));
        if (kind.equals("u32_array") && size%4==0) return new ArrayDataType(DWordDataType.dataType,size/4,4);
        return Undefined.getUndefinedDataType(size);
    }
    @Override protected void run() throws Exception {
        String[] args=getScriptArgs();
        if(args.length!=2) throw new IllegalArgumentException("Arguments: annotation-recipe.json MAS|SLA|EX");
        JsonObject root=JsonParser.parseString(Files.readString(Path.of(args[0]))).getAsJsonObject();
        JsonObject components=root.getAsJsonObject("components");
        if(!components.has(args[1])) throw new IllegalArgumentException("Unknown component; address domains must remain separate");
        JsonObject spec=components.getAsJsonObject(args[1]);
        long base=number(spec.get("base").getAsString()); int length=spec.get("length").getAsInt();
        MessageDigest digest=MessageDigest.getInstance("SHA-256"); byte[] buffer=new byte[1048576];
        for(int offset=0;offset<length;offset+=buffer.length) {
            monitor.checkCancelled(); int count=Math.min(buffer.length,length-offset);
            int read=currentProgram.getMemory().getBytes(toAddr(base+offset),buffer,0,count);
            if(read!=count) throw new IllegalStateException("Incomplete local module mapping; no metadata applied");
            digest.update(buffer,0,count);
        }
        String actual=HexFormat.of().formatHex(digest.digest());
        if(!actual.equals(spec.get("sha256").getAsString())) throw new IllegalStateException("Local module SHA-256 mismatch; no metadata applied");
        int labels=0,skipped=0;
        for(JsonElement item:spec.getAsJsonArray("symbols")) {
            monitor.checkCancelled(); JsonObject s=item.getAsJsonObject(); Address at=toAddr(number(s.get("address").getAsString()));
            if(!currentProgram.getMemory().contains(at)) { skipped++; continue; }
            String name=s.get("name").getAsString();
            if(!name.startsWith("AN_")) throw new IllegalArgumentException("Only explicit analysis labels are accepted");
            if(currentProgram.getSymbolTable().getGlobalSymbol(name,at)==null)
                currentProgram.getSymbolTable().createLabel(at,name,SourceType.USER_DEFINED);
            currentProgram.getListing().setComment(at,CommentType.EOL,"["+s.get("grade").getAsString()+" / analysis metadata] "+s.get("comment").getAsString()+" Declared mode: "+s.get("mode").getAsString()+". No instruction context or xref was forced.");
            labels++;
        }
        Map<String,StructureDataType> types=new LinkedHashMap<>(); CategoryPath category=new CategoryPath("/NikonResearchPublic/"+args[1]);
        for(JsonElement item:spec.getAsJsonArray("structures")) {
            JsonObject s=item.getAsJsonObject(); String name=s.get("name").getAsString();
            StructureDataType type=new StructureDataType(category,name,s.get("length").getAsInt());
            type.setDescription("Partial analysis definition; not an original Nikon type or verified runtime object layout. Grade: "+s.get("grade").getAsString());types.put(name,type);
        }
        for(JsonElement item:spec.getAsJsonArray("structures")) {
            JsonObject s=item.getAsJsonObject(); StructureDataType type=types.get(s.get("name").getAsString());
            for(JsonElement field:s.getAsJsonArray("fields")) {
                JsonObject f=field.getAsJsonObject(); int size=f.get("size").getAsInt();
                type.replaceAtOffset(f.get("offset").getAsInt(),resolve(f.get("type").getAsString(),size,types),size,f.get("name").getAsString(),f.get("comment").getAsString());
            }
            currentProgram.getDataTypeManager().addDataType(type,DataTypeConflictHandler.DEFAULT_HANDLER);
        }
        println("Imported analysis labels/comments="+labels+", unmapped locations skipped="+skipped+", partial types="+types.size()+". No firmware bytes, functions, instruction modes or call/data xrefs changed.");
    }
}
