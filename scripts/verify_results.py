"""Validate source snapshots, recorded CSVs and stored aggregate counters."""
import argparse,csv,gzip,io,math
from collections import defaultdict
from study_common import catalog,digest,load,study

ADDITIVE={'generated','honest_generated','delivered','honest_clean','content_clean',
          'bad_delivered','accepted','accepted_content_clean','accepted_bad',
          'accepted_honest_clean','filtered','honest_filtered','malicious_filtered'}

def verify(name):
    folder,manifest=study(name)
    for rel,expected in manifest['source_sha256'].items():
        if digest((folder/rel).read_bytes())!=expected:raise ValueError(f'Source checksum mismatch: {name}/{rel}')
    rounds=0;seen=set()
    for item in manifest['cases']:
        identity=(item['phase'],item['id'])
        if identity in seen:raise ValueError(f'Duplicate case: {name}/{identity}')
        seen.add(identity)
        record=load(folder/item['record'])
        with gzip.open(folder/item['raw'],'rb') as stream:payload=stream.read()
        if digest(payload)!=record['raw_sha256']:raise ValueError(f"CSV checksum mismatch: {name}/{item['id']}")
        sums=defaultdict(float);count=0
        for t,row in enumerate(csv.DictReader(io.StringIO(payload.decode('utf-8')))):
            if int(row['round'])!=t:raise ValueError(f"Round sequence mismatch: {name}/{item['id']}/{t}")
            def check(left,right):
                if all(k in row for k in left+right):
                    if sum(int(row[k]) for k in left)>sum(int(row[k]) for k in right):
                        raise ValueError(f"Counter invariant: {name}/{item['id']}/{t}: {left} <= {right}")
            check(['accepted_bad'],['bad_delivered'])
            check(['accepted_honest_clean'],['honest_generated'])
            for a,b,total in [('accepted_content_clean','accepted_bad','accepted'),('content_clean','bad_delivered','delivered')]:
                if all(k in row for k in [a,b,total]) and int(row[a])+int(row[b])!=int(row[total]):
                    raise ValueError(f"Counter balance: {name}/{item['id']}/{t}/{total}")
            for key in ADDITIVE & row.keys():sums[key]+=float(row[key])
            count+=1
        if count!=item['rounds']:raise ValueError(f"Wrong row count: {name}/{item['id']}")
        for key,total in sums.items():
            expected=record['overall'].get(key)
            if expected is not None and not math.isclose(total,expected,rel_tol=1e-10,abs_tol=1e-7):
                raise ValueError(f"Metric mismatch: {name}/{item['id']}/{key}: {total} != {expected}")
        if 'calibration_fixture' in record and not (folder/record['calibration_fixture']).is_file():
            raise ValueError(f"Missing calibration fixture: {name}/{item['id']}")
        rounds+=count
    if len(seen)!=manifest['missions'] or rounds!=manifest['rounds']:raise ValueError(f'Collection counts differ: {name}')
    if name=='core':
        with (folder/'fusion_stress.csv').open(newline='') as stream:
            rows=list(csv.DictReader(stream))
        if len(rows)!=7200 or any(float(x['error'])>float(x['bound'])+1e-9 for x in rows):
            raise ValueError('Fusion trial count or bound check failed')
    print(f"PASS {name}: {len(seen):,} missions, {rounds:,} rounds",flush=True)
    return len(seen),rounds

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--study');args=parser.parse_args()
    names=[args.study] if args.study else [x['id'] for x in catalog()['studies']]
    counts=[verify(name) for name in names]
    missions=sum(x[0] for x in counts);rounds=sum(x[1] for x in counts)
    if not args.study and (missions!=catalog()['missions'] or rounds!=catalog()['rounds']):raise ValueError('Catalog totals differ')
    print(f'Validated {missions:,} missions / {rounds:,} rounds.',flush=True)
if __name__=='__main__':main()
