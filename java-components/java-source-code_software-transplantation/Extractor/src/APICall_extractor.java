/*
This is a new class that is used by EvadeDroid to extract API-calls gadgets.
 */


import soot.*;
import soot.tagkit.Tag;
import java.util.List;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;


public class APICall_extractor {
    private Soot_utlilty utility = new Soot_utlilty();

    public SootClass extract_class_api_call(String feature){   	
    	
    	feature = feature.replace("/", ".");
    	String feature_part1 = feature;
    	String feature_part2 = "";
    	
    	if(feature.contains(";->")) {
    		feature_part1 = feature.split(";->")[0];
    		feature_part2 = feature.split(";->")[1] + "(";
    	}   	
	
    	

    	for (SootClass c : Scene.v().getApplicationClasses()) {
    		
            if (utility.isExcludeClass(c)) {
                continue;
            }
            for(SootField f : c.getFields()){
            	if(f.toString().contains(feature_part1) && f.toString().contains(feature_part2)){             	
                    return c;
                }            	
            }

            for (SootMethod m : c.getMethods()) {
                if (!m.hasActiveBody()) {
                    continue;
                }
                
                if (m.getName().equals("<init>") || m.getName().equals("ʼ") || m.getName().equals("ˋ")) {
                    continue;
                }

                List<ValueBox> useBoxes = m.getActiveBody().getUseAndDefBoxes();
                for (ValueBox valueBox : useBoxes) {
                    String content = valueBox.getValue().toString();
                                        
                    if(content.toString().contains(feature_part1) && content.toString().contains(feature_part2)){        	
                        return c;
                    }
                }
            }
        } 
    	
    	//if proper class does not find, we also check primitiveList by removing if (utility.isExcludeClass(c)) condition
    	//because it is not important in feature extraction
    	for (SootClass c : Scene.v().getApplicationClasses()) {
    		/*
            if (utility.isExcludeClass(c)) {
                continue;
            }
            */
            for(SootField f : c.getFields()){
            	if(f.toString().contains(feature_part1) && f.toString().contains(feature_part2)){             	
                    return c;
                }            	
            }

            for (SootMethod m : c.getMethods()) {
                if (!m.hasActiveBody()) {
                    continue;
                }                
                if (m.getName().equals("<init>") || m.getName().equals("ʼ") || m.getName().equals("ˋ")) {
                    continue;
                }
                List<ValueBox> useBoxes = m.getActiveBody().getUseAndDefBoxes();
                for (ValueBox valueBox : useBoxes) {
                    String content = valueBox.getValue().toString();
                                        
                    if(content.toString().contains(feature_part1) && content.toString().contains(feature_part2)){        	
                        return c;
                    }
                }
            }
        }    	
    	
        return null;
    }
}

