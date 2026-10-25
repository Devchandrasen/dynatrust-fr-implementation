#pragma once
#include <algorithm>
#include <cmath>
#include <deque>
#include <utility>
// Exact scalar formulas only. Packet transport, observation mapping, thresholds
// and recovery remain the declared common wrapper, not the published protocols.
namespace published {
inline double Gtms(unsigned s,unsigned f){return s+f?std::round(100.0*s*s/((s+f)*(s+1.0)))/100:.5;}
// Li et al., IEEE TIFS2013, Eqs1/5; divide the original 0..10 score by10.
// The original no-interaction rule asks for CH feedback; missing feedback=.5 is a declared wrapper choice.
inline double LdtsDirect(unsigned s,unsigned f,double feedback=.5){
 if(!s&&!f)return feedback;if(!f)return 1;
 return std::round(10.0*s/(s+f)/std::sqrt(double(f)))/10;
}
inline double LdtsMemberFeedback(unsigned positive,unsigned negative){return std::round(10.0*(positive+1)/(positive+negative+2))/10;}
inline double EdtmCommunication(unsigned s,unsigned f){return (s+.5)/(s+f+1.0);}
inline double LtmhlPenalty(double prior,bool successful){return successful?prior:std::max(0.0,prior-.1);}
struct Window {
 std::deque<std::pair<unsigned,bool>> observations;
 std::pair<unsigned,unsigned> Counts(unsigned round,unsigned width){
  while(!observations.empty()&&round-observations.front().first>=width)observations.pop_front();
  unsigned success=0;for(auto [t,good]:observations)success+=good;
  return {success,unsigned(observations.size())-success};
 }
};
}
