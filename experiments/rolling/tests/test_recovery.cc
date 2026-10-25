#include "../source/calibration-coverage.h"
#include <cassert>
#include <iostream>
int main(){
 recovery::RollingReference r;std::map<unsigned,double> a;
 for(unsigned i=0;i<10;++i)a[i]=55;
 assert(!r.Observe(a,36,1,3,2,3).available);
 a.clear();for(unsigned i=10;i<20;++i)a[i]=55;
 assert(!r.Observe(a,36,2,3,2,3).available);
 assert(r.Observe(a,36,3,3,2,3).available);
 assert(!r.Observe({},36,6,3,2,3).available); // Stale identities expire.
 r={};a.clear();for(unsigned i=0;i<18;++i)a[i]=55;
 for(unsigned t=0;t<10;++t)assert(!r.Observe(a,36,t,3,2,3).available); // Repeats cannot create quorum.
 a.clear();for(unsigned i=0;i<36;++i)a[i]=i<18?45:63;
 assert(!r.Observe(a,36,10,3,2,3).available); // Balanced separation stays unknown.
 recovery::AlarmRelease q;
 for(unsigned t=0;t<10;++t)assert(!q.Observe(true,1,t,4,.3));
 for(unsigned t=10;t<12;++t)assert(!q.Observe(true,0,t,4,.3));
 assert(q.Observe(true,0,12,4,.3)); // Three zeros plus one one average .25.
 assert(!q.Observe(false,0,14,4,.3));
 recovery::RecentBand band;
 for(unsigned i=0;i<3;++i)assert(!band.Observe(0,i,4,.75));
 assert(band.Observe(0,3,4,.75));
 assert(!band.Observe(-2,20,4,.75)); // Stale window is unavailable.
 for(unsigned i=21;i<30;++i)assert(!band.Observe(-2,i,4,.75));
 std::cout<<"Rolling identity quorum, freshness, balanced split and alarm-release checks passed\n";
}
