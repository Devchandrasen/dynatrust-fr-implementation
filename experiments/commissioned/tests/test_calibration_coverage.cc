#include "../source/calibration-coverage.h"
#include <cassert>
#include <iostream>
#include <random>
int main(){
    calibration::Baseline b;for(int i=0;i<60;++i)b.Observe(1.5);assert(b.count==60&&b.Mean()==1.5);
    std::vector<std::pair<double,double>> split={{44,1},{45,1},{46,1},{62,1},{63,1},{64,1}};
    auto r=calibration::Anchor(split,true,45,3,6,3);assert(r.available&&r.value==45);
    assert(!calibration::Anchor(split,false,45,3,6,3).available);
    assert(!calibration::Anchor(split,true,54,3,6,3).available);
    assert(!calibration::Anchor({{55,1},{56,1},{57,1}},true,45,3,6,3).available);
    assert(!calibration::Anchor({{45,1},{46,1}},true,45,3,6,3).available);
    std::mt19937 rng(19001);std::uniform_real_distribution<double> u(0,1);
    double lowest=1,mean=0;
    for(unsigned trial=0;trial<1000;++trial){
        std::vector<std::vector<double>> a(10,std::vector<double>(10));for(auto& row:a)for(auto& x:row)x=u(rng);
        std::vector<bool> allowed(10,true);allowed[trial%10]=false;
        auto g=coverage::Greedy(a,allowed,3);assert(g.size()==3);double opt=0;
        for(unsigned i=0;i<10;++i)for(unsigned j=i+1;j<10;++j)for(unsigned k=j+1;k<10;++k)if(allowed[i]&&allowed[j]&&allowed[k])opt=std::max(opt,coverage::Utility(a,{i,j,k}));
        const double ratio=coverage::Utility(a,g)/opt;assert(ratio+1e-12>=1-std::pow(2.0/3,3));lowest=std::min(lowest,ratio);mean+=ratio;
        allowed.assign(10,false);assert(coverage::Greedy(a,allowed,3).empty());
    }
    std::cout<<"calibration/anchor tests passed; 1000 exact coverage checks: mean="<<mean/1000<<" minimum="<<lowest<<"\n";
}
