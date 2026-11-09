"""Create a new, metadata-only public candidate; never import private Git refs."""
from pathlib import Path
import csv, hashlib, json, os, re, shutil
from safe_export import ROOT,BASE,PUBLIC,safe_text

NOTES={
 '1030cade':'Own Dp constructor reads configuration +0x46C; conditional software layout control, not verified pixel precision.',
 '1026357a':'Saved initializer location writes the acquired descriptor to T+0xA0; runtime instance identity is not established.',
 '10265dec':'Saved cleanup location clears T+0xA0; does not prove complete frame lifetime or synchronization.',
 '10269a6e':'Descriptor consumer path; static field propagation does not prove hardware mode took effect.',
 '1047ec00':'Saved format validator accepts selected complete byte values; layout code 0xA is not proof of 10-bit samples.',
 '102c05ee':'Selected prefix forwards descriptor address words into a stack vector; no pixel dereference established.',
 '102e53b6':'Selector dispatch forwards address vectors; selection values are not pixel bit-depth declarations.',
 '1036a5d0':'Local software address-word publication; physical ownership, buffer contents and completion remain unknown.',
 '1036a97a':'Local four-word address publication; not proof of physical DMA, valid precision or N-Log.',
 '10268ba4':'Bounded caller context; shared provider names do not identify the same queue or image type.',
 '102b3b82':'Inspected CPU path uses byte component loads/stores; excluded as a componentwise true-10-bit preserving output adapter.',
 '105671ba':'Status and separately supplied count have distinct local software roles; count units and physical completion remain unknown.',
 '105bea78':'Provided descriptor request builder; request construction is not physical card-write validation.',
}
README_EN='''# Nikon Z7 II C1.70 — genuine 10-bit N-Log internal-recording research

[中文说明](README.zh-CN.md)

**Genuine 10-bit-effective N-Log internal card recording has NOT been implemented. The original encoder's 10-bit capability is NOT established.** No confirmed accessible true-10-bit N-Log frame source has been recovered. The project does not accept 8-bit expansion, simulated Log, metadata changes or synthetic fixtures as camera success.

This is a publication snapshot of existing offline work, not new firmware analysis or a firmware release. Research execution is currently blocked on pixel-source, format/precision, ownership and hardware-interface evidence.

* [Findings and evidence matrix](docs/findings.md)
* [Architecture and data flow](docs/architecture.md)
* [HDMI / N-Log](docs/hdmi-nlog.md), [H.264](docs/encoder.md), [RAW](docs/raw.md)
* [Corrections and excluded hypotheses](docs/corrections.md)
* [Evidence definitions and limits](docs/evidence.md)
* [MAS/SLA/EX location index](indexes/functions.csv), [partial structures](indexes/structures.json), [relations](indexes/relations.csv)
* [Ghidra metadata restoration](ghidra/README.md)
* [Independent synthetic host tools and tests](tests/test_public_tools.py)
* [Third-party references and licenses](THIRD_PARTY.md), [rights notice](COPYRIGHT.md)

VERIFIED always has a stated scope. Verified original static instructions, original natural execution in a fixed QEMU model, QEMU functional assumptions, synthetic host tests and physical-camera evidence are different classes. The public indices intentionally omit original bytes, disassembly, decompilation, captures and private evidence paths. Public availability of an index is not independent verification of withheld raw evidence.

This snapshot contains no camera firmware, decrypted modules, keys, RAM/NVRAM dumps, camera identifiers or Ghidra databases. It has no CI workflows and performs no camera operations. Third-party implementations are referenced, not bundled.

Run the host-only checks with `python3 -m unittest discover -s tests -v`. Building the optional synthetic recorder requires a C++20 compiler; its format and data are self-authored test fixtures, not Nikon N-Log. No camera performance claim follows from these tests.

Publication updates are prepared locally and audited before any public push. See [synchronization](docs/synchronization.md). The private backup is never used as a Git parent or remote source for this repository. Automated refresh updates reviewed indices/tools; descriptive conclusions remain an owner-reviewed snapshot and must be revised in the publication generator before making new claims.
'''
README_ZH='''# Nikon Z7 II C1.70：真正10-bit N-Log机内录卡研究

[English](README.md)

**尚未实现真正的10-bit N-Log机内录制；原厂编码器是否具备10-bit能力也尚未证实。** 当前没有确认可持续访问的真实高位深N-Log帧源。8-bit扩展、模拟Log、修改元数据或合成测试均不算实现。

本仓库公开既有离线研究的描述性结论、地图、索引及自研工具，不发布固件。当前研究因像素来源、有效位、格式、帧所有权与硬件契约不足而受阻。本次整理没有开展新的固件逆向或实机实验。

入口：[研究结果](docs/findings.md)、[架构](docs/architecture.md)、[HDMI/N-Log](docs/hdmi-nlog.md)、[编码器](docs/encoder.md)、[RAW](docs/raw.md)、[纠错](docs/corrections.md)、[证据分级](docs/evidence.md)。

索引保留MAS/SLA/EX地址域、分析标签、ISA声明、关系和证据等级，不包含原厂指令字节、反汇编或反编译原文。AN_名称与部分结构是分析元数据，不是尼康原始符号。相同数值地址不等于同一模块、物理芯片或运行实例。

Ghidra恢复工具只导入标签、注释和部分类型；要求本地合法输入的完整SHA-256匹配，不修改固件字节、不创建虚构xref或强制函数边界。自研宿主工具只证明有限合成数据的软件性质，不证明相机像素、DMA、编码能力或写卡吞吐。

不提供固件、解密模块、密钥、RAM/NVRAM转储、设备身份、私人数据或Ghidra数据库。不包含第三方实现代码；来源与许可证见[THIRD_PARTY.md](THIRD_PARTY.md)。公开查看不自动授予通用开源许可，见[COPYRIGHT.md](COPYRIGHT.md)。

测试命令：`python3 -m unittest discover -s tests -v`。公开更新需先生成本地候选、完整历史审计和文件清单，再经确认推送；私有备份历史绝不并入公开仓库。
'''
DOCS={
'docs/findings.md':'''# Findings and evidence matrix

| Finding | Grade and scope | Locations / relationship |
|---|---|---|
| Dp has its own conditional configuration path; no D0==Dp assumption is needed for that local path | VERIFIED static locations; composite active-instance path INFERRED | MAS 1030CADE, 1026357A, 10265DEC, 10269A6E |
| Software format validation and submission fields exist | VERIFIED static; physical HDMI effect UNKNOWN | MAS 1047EC00 and descriptor consumers |
| Descriptor address words reach two q-selected software port families | VERIFIED local static expressions; hardware DMA UNKNOWN | MAS 102C05EE, 102E53B6, 1036A5D0, 1036A97A; S565–S582, H016–H017 |
| Profile/level and SPS-like configuration candidates exist | INFERRED semantics; raw configuration relationships are static findings | MAS 104B90EE / 104B949C; not evidence of High 10 support |
| A CPU conversion path narrows components to bytes | VERIFIED local static exclusion only | MAS 102B3B82; does not exclude wider upstream or other paths |
| RAW row-capacity expressions are consistent with several wider layouts under explicit unit assumptions | INFERRED; packing and actual valid bits UNKNOWN | MAS 1023994C / 1023C830 and software submission family |
| A provided-descriptor recording API has separate status/count roles | VERIFIED static software contract; count units/consumption/durability UNKNOWN | MAS 105671BA / 105BEA78 |
| Independent host fixtures preserve synthetic 10-bit codes and reject selected faults | VERIFIED finite host tests only | Self-authored tools; no Nikon pixels or camera recording |

There is no verified end-to-end sensor → accessible genuine N-Log frame → 10-bit encoder or alternative recorder → internal card path. Encoder support, silicon incapability, complete boot, menu functionality and working internal recording are not conclusions of this repository.
''',
'docs/architecture.md':'''# Architecture and data flow

The hardware/signal map retains CMOS, ISP, HDMI, encoder, DMA, memory and storage as distinct nodes. Most physical connections remain UNKNOWN. The firmware components MAS, SLA and EX are distinct address domains; component names and identical code do not establish which EXPEED chip performs an image-processing task.

See [hardware/signal map](../diagrams/hardware.mmd) and [bounded software map](../diagrams/software.mmd).

A newly recovered local software slice loads address words from descriptor field +0x34, forwards the same vector through a selector dispatch and writes four words to q-selected software address families. Under valid objects, stable context and no overwrite, q=0 selects 20380218/20380310 groups and q=1 selects 20380228/20380320 groups, with the software bank term derived from J+4. This is address programming, not pixel access or physical-address proof.

The fixed view B2363298 contains descriptor/control information and is excluded as a frame body. Selection/retry fields are also control data. The real producer, image type, active address, width, stride, packing, valid precision, allocation/reuse and completion synchronization have not been established.

Original natural execution was observed at a bounded startup copy-request call in an unchanged fixed QEMU setup. That does not show the video path was reached, complete boot or recording. QEMU image-generation laws and completion conventions remain separate functional assumptions.
''',
'docs/hdmi-nlog.md':'''# HDMI / N-Log boundary

Settings 0x126D → 0x16A5 and the recording-configuration field +0x46C form software control evidence. Settings 0x1688 / 0x16BF have conditional propagation. These are software identifiers/fields, not proven hardware register addresses.

The descriptor families behind D0 and Dp use different normal containers. Dp's own constructor at MAS 1030CADE reads its supplied configuration; the local layout can reach existing submission code under explicit gates without assuming D0==Dp. Active object identity and configuration timing remain UNKNOWN.

The validator at MAS 1047EC00 operates on a complete byte field with selected accepted values. A layout code, including 0xA, does not establish 10-bit sample precision. Software HDMI capability/configuration queries are not themselves EDID negotiation or actual pixel transport.

The N-Log processing stage, true high-depth buffer, CPU/DMA accessibility, connection/negotiation requirements and whether precision is retained before or after accessible memory remain UNKNOWN.
''',
'docs/encoder.md':'''# H.264 capability remains UNKNOWN

Recovered event, configuration, address-record and software-port relationships do not establish the complete encoder hardware contract. Profile/level interpretations and SPS-like parameters are INFERRED where supported by comparisons; container widths, defaults and HDMI output capability are insufficient evidence of encoder precision.

Neither genuine 10-bit encoding support nor silicon incapability has been proved. Required evidence includes actual input packing/valid bits, encode versus decode direction, active DMA/ownership, output bitstream syntax and original execution under the intended mode.

The original internal recording default is not used to rule out silicon capability. Conversely, a format enum or a wider coefficient/storage field is not used to claim High 10 support. The public indices are navigation aids, not an implemented encoder patch.
''',
'docs/raw.md':'''# RAW is not N-Log

Selected original software expressions calculate row capacities proportional to 2W, floor(7W/4) and floor(3W/2), with bounded storage/alignment and an explicit special branch. Only if W counts samples and the step counts bytes are these consistent with 16/14/12-bit row capacities. This does not recover packing, endianness, valid precision or the Log processing stage.

Capture-side software arrays and the newer input-address vector have not been proved to be the same objects, values or generations. Matching field offsets, compatible geometry and shared provider functions do not close that gap. Confidence/geometry grids and software descriptors are excluded as verified video-frame bodies.

RAW analysis may help recover image interfaces, but recording RAW or applying a self-authored Log transform is not presented as the requested factory N-Log internal-recording result.
''',
'docs/corrections.md':'''# Corrections and rejected shortcuts

* D0 and Dp: similar layouts and shared configuration do not prove runtime object equality or copying.
* Initial address translation: an earlier table-base interpretation was withdrawn; the corrected local startup projection still does not prove active video VA/PA mappings.
* A hit spanning an adjacent identifier and H264Driver text was not a valid original driver name or entry point.
* Backend 9 geometry/distortion data is not a video-frame buffer.
* Byte-component CPU output is excluded only for that inspected path, not for the entire chip.
* A shared queue/provider function does not merge confidence-map and RAW instances.
* A positive return, an event flag, model completion or successful decompilation is not proof of valid pixels or durable recording.
* Auto-analysis function counts and publication/map size are not evidence coverage or engineering success.

Historical failures, source-coverage gaps and superseded interpretations remain in the local screened history. Public descriptive summaries omit original byte and disassembly evidence rather than republishing it.
''',
'docs/evidence.md':'''# Evidence definitions

VERIFIED means only the explicitly inspected property: for example an original local static field relation, finite synthetic test or a stated observation in a fixed model. INFERRED is conditional interpretation. UNKNOWN is an unproved required fact, not a negative hardware-capability result.

Evidence classes are separate: original static code; original natural execution in a fixed QEMU model; QEMU functional implementation assumptions; host synthetic fixtures; historical externally supplied physical observations; new physical-camera validation. This project performed no new physical-camera validation.

Each indexed location retains component, address, stated instruction mode, analysis label and grade. Restored labels do not prove function boundaries, reachability, semantic types or hardware identity. No fictional call/data xrefs are created.

Raw original evidence, camera captures and full Ghidra projects are intentionally not public. A researcher needs lawfully obtained matching local components and the relevant local evidence for instruction-level independent reproduction. The public package does not claim complete public end-to-end reproducibility.
''',
'docs/synchronization.md':'''# Separate synchronization

Public preparation never clones, fetches or merges the private repository. Run the publication manager against a local source workspace to refresh this repository, then audit all reachable history and inspect PUBLIC-FILES.txt and the manifest. Default operation is local only.

A public push additionally requires the operator's explicit approval of the current manifest digest. The push helper only permits the main ref and confirms the target visibility immediately before transfer. No CI or release attachments are configured.

The private backup keeps screened research-history commits separately and appends backup metadata on main. Later updates must fast-forward the screened history; a sanitizer-policy change must not silently rewrite published history. Original firmware/reference bytes and databases remain local and are never synchronized.

Use a clean destination and a new ignored work directory for each run. Review the staged paths and diff before committing a prepared update:

```sh
python3 publication-tools/sync.py private --source /path/to/local-research --destination /path/to/private-backup --workdir /path/to/ignored-work/private-run --prepare-only
python3 publication-tools/sync.py public --source /path/to/local-research --destination /path/to/public-release --workdir /path/to/ignored-work/public-run --prepare-only
```

The staged paths/diff are written to the work directory. Without `--prepare-only`, preparation commits the local update and audits every reachable history tree/blob. A completed local update does not push. Refreshes regenerate reviewed indices and tools; prose findings must be separately reviewed in build_public.py. New firmware baselines fail closed. Source Git history is read only.

Network transfer is a separate invocation using `--push --owner ACCOUNT --gh /path/to/gh`, retaining the same source/destination/workdir arguments. Configure the intended GitHub CLI account normally first; the manager never starts authentication. If a separate CLI configuration directory is used, set GH_CONFIG_DIR for that invocation. The public invocation additionally requires `--approved-manifest-sha256 DIGEST`, after explicit owner review of that exact version. Credentials stay in the CLI configuration, outside both repositories. Never use git push --mirror, --all or --force.

No GitHub Actions, automatic scheduled publication or release uploads are installed. Before publication, independently review all new material; pattern rules do not establish copyright clearance or detect every secret. A policy change that alters old screened commits requires a new independently reviewed backup generation, not a force update of published history.
''',
'COPYRIGHT.md':'''# Rights notice

No blanket open-source license has been selected for the original research material and tools. Rights are retained; public access is not a general license to reuse. Any later license grant requires an explicit owner decision.

Nikon firmware and proprietary assets remain with their respective rights holders. No firmware license is granted here. No third-party implementation code, vendor binaries or original firmware snippets are bundled. Linked projects and dependencies retain their own licenses.
''',
'THIRD_PARTY.md':'''# Primary references and licenses

| Reference | Pinned revision / license basis | Redistribution here |
|---|---|---|
| [nightglasses/z7ii-qemu](https://github.com/nightglasses/z7ii-qemu) | baa8aa78e7d36dcec20c7c08b8c6b092840eafce; inspected Nikon device source files declare GPL-2.0-or-later; verify each upstream file | No implementation code |
| [QEMU](https://www.qemu.org/) | submodule 4fc49f46dc95d4a27de2509e7fceb2931e91faeb; COPYING/LICENSE describe GPLv2 and per-file compatible licenses | None |
| [WonderLantern/nikon-fw-key-tool](https://github.com/WonderLantern/nikon-fw-key-tool) | 33426e892afd329a3b366b73776bcf53b9ac4ee8; bundled LICENSE is GPLv3 | No implementation, keys or tables |
| [Fly-beep-256/z62_qemu](https://github.com/Fly-beep-256/z62_qemu) | 1a79b9dbdc7bef89f942baf0335b80cb6ba47e71; NOTICE declares GPL-2.0-or-later original project material and separate upstream terms | None |
| [Ghidra](https://github.com/NationalSecurityAgency/ghidra) | local 12.2 PUBLIC; root Apache-2.0 license, other bundled dependencies have separate terms | Only independently authored API-using scripts; no libraries |
| [GitHub CLI](https://github.com/cli/cli) | official 2.103.3 deployment used locally; MIT license | No binary |

Python, NumPy, compiler and optional media tools must be obtained separately under their applicable licenses. Vendor/model documentation is used as navigation and qualified source claims, not as a recovered EXPEED hardware specification. No permission to redistribute Nikon proprietary material is inferred from the licenses of these projects.
''',
}

def write(rel,text):
    if rel.endswith('.mmd'):text=re.sub(r'-\. "([^"]+)" \.->',r'-.->|"\1"|',text)
    p=PUBLIC/rel;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(text)
def dump(rel,obj):write(rel,json.dumps(obj,ensure_ascii=False,indent=2)+'\n')
def csvfile(rel,rows,fields):
    p=PUBLIC/rel;p.parent.mkdir(parents=True,exist_ok=True)
    with p.open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=fields,lineterminator='\n');w.writeheader();w.writerows(rows)

def build_public():
    assert not PUBLIC.exists(),'Use refresh_public for an existing candidate; never overwrite silently'
    PUBLIC.mkdir()
    write('README.md',README_EN);write('README.zh-CN.md',README_ZH)
    for p,s in DOCS.items():write(p,s)
    write('.gitignore','__pycache__/\n*.pyc\n/build/\n/.cache/\n/firmware/\n*.bin\n*.rom\n*.img\n*.gpr\n*.rep/\n*.pcap*\n.env*\n*.key\n*.pem\n')
    write('diagrams/hardware.mmd','''flowchart LR
  CMOS -. "UNKNOWN" .-> ISP
  ISP -. "true N-Log pixel source UNKNOWN" .-> RAM
  ISP -. "physical upstream route UNKNOWN" .-> HDMI
  RAM -. "format and valid bits UNKNOWN" .-> ENCODER
  RAM -. "ownership and completion UNKNOWN" .-> DMA
  DMA -. "bus and card integration UNKNOWN" .-> STORAGE
  MAS -->|VERIFIED static address-word publication only| PORTS
  PORTS -. "physical owner / DMA binding UNKNOWN" .-> DMA
  QEMU[QEMU functional models] -. "not physical capability proof" .-> ISP
''')
    write('diagrams/software.mmd','''flowchart LR
  P[Configuration field +0x46C] -->|VERIFIED local static| DP[Dp own constructor]
  DP -. "active instance/generation INFERRED" .-> SUBMIT[Software format submission]
  PROVIDER[Actual producer UNKNOWN] -.-> DESC[Descriptor address field +0x34]
  DESC -->|VERIFIED static| VECTOR[Address vector]
  VECTOR -->|VERIFIED static dispatch| PORTS[q-selected software address writes]
  PORTS -. "pixels / precision / completion UNKNOWN" .-> FRAME[Accessible genuine N-Log frame NOT FOUND]
  FRAME -. "integration UNKNOWN" .-> REC[Candidate recording interface]
''')
    current=json.loads((ROOT/'research/maps/CURRENT.json').read_text())
    components=json.loads((ROOT/'research/maps/COMPONENTS.json').read_text())
    component_specs=[('MAS',current['version'],'02_eg1840_mas_01700.payload.bin',0x10020000),('SLA',components['SLA']['version'],'04_eg1840_sla_01700.payload.bin',0x10020000),('EX',components['EX']['version'],'00_ex1840_013000.bi.payload.bin',0x08000000)]
    recipes={};locations=[];structures=[];nodes=[];edges=[]
    for component,version,filename,base in component_specs:
        a=json.loads((ROOT/'research/maps'/version/'annotations.json').read_text());g=json.loads((ROOT/'research/maps'/version/'graph.json').read_text())
        entries=[('function_or_boundary_label',e) for e in a.get('functions',[])]+[('location_label',e) for e in a.get('locations',[])] if component=='MAS' else [('component_entry_label',e) for e in a['entries']]
        symbols=[]
        for record_kind,e in entries:
            addr=e['address'];name=e.get('analysis_name',e.get('name',''))
            if not name:continue
            grade=e.get('grade','UNKNOWN');mode=e.get('mode','Thumb')
            msg=NOTES.get(format(int(addr,16),'x'),f'{grade} for the saved local analysis location. Physical behavior, effective precision and reachability are not established by this label.')
            symbols.append(dict(address=addr,name=name,grade=grade,mode=mode,comment=msg+' Analysis label, not an original Nikon symbol or proof of function boundary.'))
            locations.append(dict(component=component,address=addr,record_kind=record_kind,instruction_mode=mode,analysis_label=name,grade=grade,scope='Saved local analysis metadata; not physical capability, confirmed function boundary or runtime identity proof'))
        ss=[]
        for s in a.get('structures',[]):
            fields=[]
            for f in s['fields']:
                if len(f)>=4 and isinstance(f[1],int):offset,size,kind,name=f[:4]
                else:offset,name=f[:2];size=4;kind='u32'
                fields.append(dict(offset=offset,size=size,type=kind,name=name,comment='Partial analysis field; semantic interpretation and runtime object identity are not forced.'))
            v=dict(name=s['name'],length=s['length'],grade=s.get('grade','INFERRED'),fields=fields)
            ss.append(v);structures.append(dict(component=component,**v))
        expected=a.get('mas_sha256',a.get('input_sha256'))
        approved={'MAS':'a218daf0234cebc11ed3b9277208a884eace242a32af3a60ef25081ce6221ae6','SLA':'3677d4663b6c2c648ccc0133600b3de9ddf796bfdd6b9bc9a888e358e361877c','EX':'1c1c0aed61b9f4abd145f076eefaff0777136c0f5c9db32592de287c3e907027'}
        if expected!=approved[component]:raise RuntimeError('New firmware/module baseline requires explicit publication review')
        lengths={'MAS':38239096,'SLA':8834368,'EX':524288}
        recipes[component]=dict(component=component,base=hex(base),length=a.get('rom_bytes',lengths[component]),sha256=expected,snapshot=version,symbols=symbols,structures=ss)
        for n in g.get('nodes',[]):
            nodes.append(dict(component=component,id=n['id'],address=n.get('address') or '',analysis_label=n.get('analysis_name',n['id']),layer=n.get('layer','software'),grade=n.get('grade','UNKNOWN')))
        for e in g.get('edges',[]):
            kind=e.get('kind','');scope=e.get('scope','Qualified local evidence only')
            cls='scoped static analysis or interpretation; see scope'
            if e['grade']=='UNKNOWN':cls='unverified relationship'
            elif 'natural' in kind.lower():cls='original natural execution in fixed QEMU; not physical camera'
            elif e['id'] in ('H011','H014','H015') or 'qemu' in kind.lower() or 'qemu' in scope.lower() or 'hostsource' in scope.lower().replace(' ',''):cls='QEMU model source or host observation; see scope'
            edges.append(dict(component=component,id=e['id'],source=e['source'],target=e['target'],grade=e['grade'],evidence_class=cls,relationship=kind,site=e.get('site',''),scope=safe_text(scope),conditions=safe_text(e.get('conditions','See evidence scope'))))
    dump('indexes/annotation-recipe.json',dict(schema=1,qualification='Metadata only; no original bytes or disassembly. Labels and partial types are analysis hypotheses unless scoped otherwise.',components=recipes))
    dump('indexes/structures.json',structures)
    # The original EX snapshot contains edge IDs without a node table. Preserve
    # them as explicit UNKNOWN index endpoints, never inferred function addresses.
    present={(n['component'],n['id']) for n in nodes}
    for edge in edges:
        for endpoint in (edge['source'],edge['target']):
            key=(edge['component'],endpoint)
            if key not in present:
                nodes.append(dict(component=key[0],id=key[1],address='',analysis_label=key[1],layer='unresolved_index_endpoint',grade='UNKNOWN'));present.add(key)
    csvfile('indexes/functions.csv',locations,['component','address','record_kind','instruction_mode','analysis_label','grade','scope'])
    csvfile('indexes/nodes.csv',nodes,['component','id','address','analysis_label','layer','grade'])
    csvfile('indexes/relations.csv',edges,['component','id','source','target','grade','evidence_class','relationship','site','scope','conditions'])
    for name in ('u10_recorder.cpp','check_u10_recorder.py','recover_u10_prefix.py','export_u10_planar.py','lossless_blocks.py','recording_envelope.py','storage_span_plan.py','status_count_sink.py'):
        p=PUBLIC/'tools/prototypes'/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes((ROOT/'tools/prototypes'/name).read_bytes())
    write('ghidra/README.md','''# Restore analysis metadata locally

Use a separate analysis project containing a lawfully obtained matching raw component at the listed base. Run RestorePublicAnnotations.java with two arguments: path to indexes/annotation-recipe.json and MAS, SLA or EX. The script hashes the complete local module before changing metadata and refuses mismatches.

It restores AN_ labels, evidence comments and partial type definitions only. It does not modify bytes, create code/functions, force ARM/Thumb context, invent xrefs or populate RAM. Data types are not applied to runtime objects. Components remain separate even when numerical addresses overlap. Back up your analysis project first.

This recipe intentionally omits proprietary byte guards and original excerpts. Full-module SHA-256 verification remains required. A label is not a recovered Nikon symbol, a proven function boundary or hardware validation.
''')
    template=Path(__file__).resolve().parent/'templates'
    for rel in ('ghidra/RestorePublicAnnotations.java','tests/test_public_tools.py','TESTING.md','validation/initial-packaging.json'):
        src=template/rel
        if not src.is_file():raise RuntimeError('Missing reviewed publication template: '+rel)
        dest=PUBLIC/rel;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(src,dest)
    print(json.dumps(dict(locations=len(locations),structures=len(structures),relations=len(edges),nodes=len(nodes),public_created=True)))

if __name__=='__main__':build_public()
