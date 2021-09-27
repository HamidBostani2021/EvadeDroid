

import soot.*;

import soot.tagkit.Tag;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.List;


public class Intent_extractor {
	
	
	 private Soot_utlilty utility = new Soot_utlilty();

	    public SootClass extract_class_intent(String feature){
	    	
	    	
	    	StringBuilder str= new StringBuilder();
	    	for (SootClass i: Scene.v().getApplicationClasses()) {
	          	//System.out.println(i.getName());
		      	str.append(i.getName());
		      	
		      	str.append("\n*****Fields******\n");
		      	
		        for(SootField f: i.getFields()) {
		        	str.append(f);
		          	//System.out.println(f);
		        }
		        
		        str.append("\n*****Methods******\n");
		        
	          	for(SootMethod sm: i.getMethods()) {    
	          		if (!sm.hasActiveBody()) {
	                    continue;
	                }
	          		str.append(sm.retrieveActiveBody());
	              	//System.out.println(sm.retrieveActiveBody());
	          		
	          		List<Tag> tags = sm.getActiveBody().getTags();
	          		str.append(tags);
	          		/*
	          		List<ValueBox> useBoxes = sm.getActiveBody().getUseAndDefBoxes();
	                for (ValueBox valueBox : useBoxes) {
	                    String content = valueBox.getValue().toString();
	                    str.append(content);
	                }
	                */
	                str.append("\n*****End Methods******\n");
	            }
	        }
	    	File file = new File("C:\\GitLab\\end-to-end_black-box_evasion_attack\\data\\stored-components\\fileNew1.jimple");
	    	BufferedWriter writer = null;
	    	try {
	    	    writer = new BufferedWriter(new FileWriter(file));
	    	    writer.write(str.toString());
	    	} 
	    	catch(IOException e) {
	    		System.out.print(e.toString());    	
	    	}
	    	
	    	/*
	    	feature = "ACTION" + feature.split("action")[1].replace(".", "_");
	    	
	    	for (SootClass c : Scene.v().getApplicationClasses()) {
	    		
	    		if (utility.isExcludeClass(c)) {
	                continue;
	            }
	            
	    		for(SootField f: c.getFields()) {
	    			//System.out.println(f);
	    			if (f.toString().contains(feature) == true)
		            	return c;
		        } 
	    		
	    		for(SootMethod sm: c.getMethods()) {    
	          		if (!sm.hasActiveBody()) {
	                    continue;
	                }
	          		List<ValueBox> useBoxes = sm.getActiveBody().getUseAndDefBoxes();
	                for (ValueBox valueBox : useBoxes) {
	                    String content = valueBox.getValue().toString();
	                    if (content.contains(feature)) {
	                        return c;
	                    }
	                }
	            }
	        }*/
	        return null;
	    }
	}

