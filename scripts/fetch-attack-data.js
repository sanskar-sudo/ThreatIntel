// scripts/fetch-attack-data.js
// Fetches live MITRE ATT&CK STIX data and injects it into threat-actors.html

import fetch from 'node-fetch';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const STIX_URL =
  'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-16.1.json';

const HTML_FILE = path.join(__dirname, '..', 'threat-actors.html');

const TACTIC_ORDER = [
  'reconnaissance', 'resource-development', 'initial-access', 'execution',
  'persistence', 'privilege-escalation', 'defense-evasion', 'credential-access',
  'discovery', 'lateral-movement', 'collection', 'command-and-control',
  'exfiltration', 'impact'
];

// ── origin inference ──────────────────────────────────────────────────────
function inferOrigin(name, aliases, description) {
  const text = [name, ...(aliases || []), description || ''].join(' ').toLowerCase();
  if (/apt(10|15|17|18|19|27|30|31|40|41)|mustang panda|hafnium|volt typhoon|salt typhoon|lucky mouse|ke3chang|axiom|winnti|deep panda|bronze|comment crew|gallium|aquatic panda|earth lusca|tonto team/.test(text)) return 'China';
  if (/apt28|apt29|cozy bear|fancy bear|sandworm|turla|wizard spider|gamaredon|sofacy|carbon spider|voodoo bear|dragonfly|energetic bear|indrik spider/.test(text)) return 'Russia';
  if (/lazarus|apt38|kimsuky|andariel|stardust chollima|silent chollima|labyrinth chollima|bluenoroff|apt37|scarCruft|higaisa/.test(text)) return 'North Korea';
  if (/apt33|apt34|apt35|apt39|charming kitten|magic hound|helix kitten|oilrig|muddywater|fox kitten|lyceum|agrius|ajax security|leafminer|silent librarian/.test(text)) return 'Iran';
  if (/equation group|longhorn/.test(text)) return 'USA';
  if (/darkhotel/.test(text)) return 'South Korea';
  if (/transparent tribe|apt36|gorgon/.test(text)) return 'Pakistan';
  if (/patchwork|sidewinder/.test(text)) return 'India';
  if (/molerats|wirte|volatile cedar/.test(text)) return 'Palestine';
  if (/apt-c-36|blind eagle/.test(text)) return 'South America';
  if (/poseidon/.test(text)) return 'Brazil';
  if (/silverterrier/.test(text)) return 'Nigeria';
  return 'Unknown';
}

// ── main ──────────────────────────────────────────────────────────────────
async function main() {
  console.log('Fetching MITRE ATT&CK STIX data...');
  const res = await fetch(STIX_URL);
  if (!res.ok) throw new Error(`Failed to fetch STIX data: HTTP ${res.status}`);
  const stix = await res.json();

  console.log(`Parsing ${stix.objects.length} STIX objects...`);
  const objects = stix.objects;

  // separate by type
  const groups     = objects.filter(o => o.type === 'intrusion-set'  && !o.revoked && !o.x_mitre_deprecated);
  const techniques = objects.filter(o => o.type === 'attack-pattern' && !o.revoked && !o.x_mitre_deprecated);
  const malware    = objects.filter(o => o.type === 'malware'        && !o.revoked && !o.x_mitre_deprecated);
  const tools      = objects.filter(o => o.type === 'tool'           && !o.revoked && !o.x_mitre_deprecated);
  const campaigns  = objects.filter(o => o.type === 'campaign'       && !o.revoked && !o.x_mitre_deprecated);
  const rels       = objects.filter(o => o.type === 'relationship');

  console.log(`Found: ${groups.length} groups, ${techniques.length} techniques, ${malware.length + tools.length} software, ${campaigns.length} campaigns`);

  // helpers
  const attackId = obj => obj.external_references?.find(r => r.source_name === 'mitre-attack')?.external_id || '';
  const tacticOf = tech => tech.kill_chain_phases?.map(p => p.phase_name).filter(t => TACTIC_ORDER.includes(t)) || [];

  // build indexes
  const techById  = {};
  techniques.forEach(t => techById[t.id] = t);
  const swById = {};
  [...malware, ...tools].forEach(s => swById[s.id] = s);
  const groupById = {};
  groups.forEach(g => groupById[g.id] = g);
  const campById = {};
  campaigns.forEach(c => campById[c.id] = c);

  // build group -> techniques, software, campaigns from relationships
  const groupTechs = {};
  const groupSw    = {};
  const groupCamps = {};
  rels.forEach(r => {
    const src = r.source_ref, tgt = r.target_ref;
    if (r.relationship_type === 'uses') {
      if (src.startsWith('intrusion-set--') && tgt.startsWith('attack-pattern--')) {
        if (!groupTechs[src]) groupTechs[src] = new Set();
        groupTechs[src].add(attackId(techById[tgt] || {}));
      }
      if (src.startsWith('intrusion-set--') && (tgt.startsWith('malware--') || tgt.startsWith('tool--'))) {
        if (!groupSw[src]) groupSw[src] = new Set();
        groupSw[src].add(attackId(swById[tgt] || {}));
      }
    }
    if (r.relationship_type === 'attributed-to' && tgt.startsWith('intrusion-set--')) {
      if (!groupCamps[tgt]) groupCamps[tgt] = new Set();
      const camp = campById[src];
      if (camp) groupCamps[tgt].add(camp.name);
    }
  });

  // ── build DATA.groups ──
  const outGroups = groups.map(g => ({
    id:        attackId(g),
    name:      g.name,
    aliases:   (g.aliases || []).filter(a => a !== g.name).slice(0, 6),
    origin:    inferOrigin(g.name, g.aliases, g.description),
    desc:      (g.description || '').slice(0, 400),
    techs:     [...(groupTechs[g.id] || [])].filter(Boolean),
    sw:        [...(groupSw[g.id]    || [])].filter(Boolean),
    campaigns: [...(groupCamps[g.id] || [])],
  })).filter(g => g.id); // only groups with ATT&CK IDs

  // ── build DATA.techniques ──
  const outTechniques = techniques
    .filter(t => attackId(t) && !attackId(t).includes('.')) // skip sub-techniques for brevity
    .map(t => ({
      id:     attackId(t),
      name:   t.name,
      tactic: tacticOf(t)[0] || 'unknown',
      desc:   (t.description || '').slice(0, 300),
    }));

  // ── build DATA.software ──
  const outSoftware = [...malware, ...tools].map(s => ({
    id:      attackId(s),
    name:    s.name,
    type:    s.type,
    aliases: (s.x_mitre_aliases || []).filter(a => a !== s.name).slice(0, 4),
    desc:    (s.description || '').slice(0, 300),
  })).filter(s => s.id);

  // ── build DATA.campaigns ──
  const outCampaigns = campaigns.map(c => {
    // find attributed group
    const groupRel = rels.find(r => r.source_ref === c.id && r.relationship_type === 'attributed-to');
    const group = groupRel ? groupById[groupRel.target_ref]?.name || '' : '';
    const firstSeen = c.first_seen ? new Date(c.first_seen).getFullYear().toString() : '';
    const lastSeen  = c.last_seen  ? new Date(c.last_seen).getFullYear().toString()  : '';
    const year = firstSeen && lastSeen && firstSeen !== lastSeen ? `${firstSeen}-${lastSeen}` : (firstSeen || '');
    return {
      id:    attackId(c),
      name:  c.name,
      group,
      year,
      desc:  (c.description || '').slice(0, 300),
    };
  }).filter(c => c.id);

  const updatedAt = new Date().toISOString().split('T')[0];

  // ── inject into HTML ──
  console.log('Reading HTML file...');
  let html = fs.readFileSync(HTML_FILE, 'utf-8');

  const dataBlock = `const DATA = ${JSON.stringify({
    updatedAt,
    groups:     outGroups,
    techniques: outTechniques,
    software:   outSoftware,
    campaigns:  outCampaigns,
  }, null, 2)};`;

  // replace the existing DATA block between markers
  const startMarker = '/* ATTACK_DATA_START */';
  const endMarker   = '/* ATTACK_DATA_END */';

  if (html.includes(startMarker) && html.includes(endMarker)) {
    const before = html.slice(0, html.indexOf(startMarker) + startMarker.length);
    const after  = html.slice(html.indexOf(endMarker));
    html = before + '\n' + dataBlock + '\n' + after;
  } else {
    throw new Error('Could not find ATTACK_DATA_START / ATTACK_DATA_END markers in threat-actors.html');
  }

  fs.writeFileSync(HTML_FILE, html, 'utf-8');
  console.log(`Done. Injected ${outGroups.length} groups, ${outTechniques.length} techniques, ${outSoftware.length} software, ${outCampaigns.length} campaigns.`);
  console.log(`Updated: ${updatedAt}`);
}

main().catch(err => { console.error(err); process.exit(1); });
