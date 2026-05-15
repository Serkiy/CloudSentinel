using System;
using System.Linq;
using CloudSentinel.Model;

namespace CloudSentinel.Scoring
{
    public class RiskScorer
    {
        public void Score(ScanResult result)
        {
            int criticalCount = result.Critical.Count();
            int highCount     = result.High.Count();
            int mediumCount   = result.Medium.Count();
            int lowCount      = result.Low.Count();

            int rawScore = (criticalCount * 10)
                         + (highCount     * 7)
                         + (mediumCount   * 4)
                         + (lowCount      * 1);

            int finalScore = Math.Min(rawScore, 100);

            string grade;
            if      (finalScore <= 20) grade = "A";
            else if (finalScore <= 40) grade = "B";
            else if (finalScore <= 60) grade = "C";
            else if (finalScore <= 80) grade = "D";
            else                       grade = "F";

            result.RiskScore = finalScore;
            result.Grade     = grade;
        }
    }
}