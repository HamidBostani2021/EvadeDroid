import java.util.List;

import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.ValueBox;

import soot.SootField;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

public class APIPermissions_extractor {
	private Soot_utlilty utility = new Soot_utlilty();

    public SootClass extract_class_api_permission(String feature){
    	    	    	
    	/*
    	StringBuilder str= new StringBuilder();
    	for (SootClass i: Scene.v().getApplicationClasses()) {
          	//System.out.println(i.getName());
	      	str.append(i.getName());
	        for(SootField f: i.getFields()) {
	        	str.append(f);
	          	//System.out.println(f);
	        }
          	for(SootMethod sm: i.getMethods()) {    
          		if (!sm.hasActiveBody()) {
                    continue;
                }
          		str.append(sm.retrieveActiveBody());
              	//System.out.println(sm.retrieveActiveBody());
            }
          	str.append("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
        }
    	File file = new File("C:\\GitLab\\end-to-end_black-box_evasion_attack\\data\\stored-components\\file_495.jimple");
    	BufferedWriter writer = null;
    	try {
    	    writer = new BufferedWriter(new FileWriter(file));
    	    writer.write(str.toString());
    	} 
    	catch(IOException e) {
    		System.out.print(e.toString());    	
    	}
    	*/
    	
    	
    	for (SootClass c : Scene.v().getApplicationClasses()) {
            if (utility.isExcludeClass(c)) {
                continue;
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
                    if (content.contains(feature)) {
                        return c;
                    }
                }
            }
        }
    	
    	//Hamid: if proper class does not find, we also check primitiveList by removing if (utility.isExcludeClass(c)) condition
    	//because it is not important in feature extraction
    	for (SootClass c : Scene.v().getApplicationClasses()) {
            /*
    		if (utility.isExcludeClass(c)) {
                continue;
            } 
            */           
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
                    if (content.contains(feature)) {
                        return c;
                    }
                }
            }
        }
    	
    	return null;
    }
}
