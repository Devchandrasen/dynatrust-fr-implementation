#include "../ns3/v2a/trust-v2.h"
#include <fstream>
#include <iomanip>
#include <random>
#include <tuple>
#include <iostream>
int main(int argc,char** argv){
 if(argc!=2)return 2;std::ofstream out(argv[1]);if(!out)return 3;
 out<<"n,theta,actual_theta,alpha,spread,attack,seed,error,honest_trimmed,honest_count,bad_retained,retained,bound\n"<<std::setprecision(10);
 for(unsigned n:{8u,16u,32u})for(double theta:{0.0,.1,.2,.4,.5})for(double alpha:{0.0,.1,.2,.3})for(double spread:{.05,.25})for(unsigned attack:{0u,1u})for(unsigned seed=201;seed<=230;++seed){
   dynatrust::Parameters p;p.alpha=alpha;p.delta=.2;
   std::mt19937 rng(seed*100+n*7+std::lround(theta*1000));std::uniform_real_distribution<double> distribution(.8-spread,.8+spread);
   unsigned bad=std::lround(theta*n);std::vector<double> values;std::vector<std::tuple<double,bool>> audit;double gamma=0;
   for(unsigned j=0;j<n;++j){bool malicious=j<bad;double x=malicious?(attack==0?0:.7):dynatrust::Clamp(distribution(rng));values.push_back(x);double clipped=std::clamp(x,.5,.9);audit.push_back({clipped,malicious});if(!malicious)gamma=std::max(gamma,std::abs(clipped-.8));}
   std::stable_sort(audit.begin(),audit.end());unsigned k=std::floor(alpha*n),m=n-2*k,htrim=0,bret=0;
   for(unsigned j=0;j<n;++j){bool retained=j>=k&&j<n-k;if(retained&&std::get<1>(audit[j]))++bret;if(!retained&&!std::get<1>(audit[j]))++htrim;}
   double error=std::abs(dynatrust::Fusion(values,.7,p)-.8),bound=gamma+std::min(bad,m)*.3/m;
   if(error>bound+1e-12)return 4;
   out<<n<<','<<theta<<','<<double(bad)/n<<','<<alpha<<','<<spread<<','<<(attack?"central":"extreme")<<','<<seed<<','<<error<<','<<htrim<<','<<n-bad<<','<<bret<<','<<m<<','<<bound<<'\n';
 }
 std::cout<<"Fusion stress and finite-sample bound checks passed\n";
}
