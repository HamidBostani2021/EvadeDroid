
/*
This Java component, which is responsible for organ harvesting, is originally implemented in [1]. 
Besides doing some modifications, we extended this component to extract API-calls gadgets.
 
[1] Intriguing Properties of Adversarial ML Attacks in the Problem Space 
    [S&P 2020], Pierazzi et al.

 */

import org.apache.commons.io.FileUtils;
import soot.*;
import soot.options.Options;
import java.io.*;
import java.lang.reflect.TypeVariable;
import java.util.*;
import javax.security.auth.callback.LanguageCallback;
import static java.lang.System.exit;



public class Instrumenter {


    private static String apkPath = "";

    private static String feature = "";

    private static String Feat_Type = "";

    public static String output_dir = "";

    protected static String jarsPath = "";

    public static int output_format = Options.output_format_jimple;

    public static boolean DEBUG = false;

    private static boolean slice_found = false;


    public static void main(String[] args) {

        if(args.length == 5){
            feature = args[0];
            apkPath = args[1];
            Feat_Type = args[2];
            output_dir = args[3];
            jarsPath = args[4]+"platforms";
        }else if(args.length == 6){
            feature = args[0];
            apkPath = args[1];
            Feat_Type = args[2];
            output_dir = args[3];
            jarsPath = args [4]+"platforms";
            DEBUG = Boolean.parseBoolean(args[5]);

        }else{
            System.out.println("Wrong arguments, invoation should be like:\njava -jar extractor.jar <feature> <path_to_goodware> <feature_type> <path_for_save_jimples>\n");
            exit(0);
        }        
        

        Soot_utlilty config = new Soot_utlilty();
        String name_root_folder = "";
        if(feature.startsWith("http")){           
             name_root_folder = feature.replace(".","_").replace("/","£").replace(":","^").replace("?","@").replace(">", "(").replace(";", ")");
        }else{
            name_root_folder = feature.replace(".","_").replace("/","£").replace("b'","").replace("'","").replace(">", "(").replace(";", ")");

        }
        
        
        //change feature names derived from smali to a proper feature name for jimple
        if(feature.startsWith("Read/WriteExternalStorage")) {
        	feature = "getExternalStorageDirectory";
        }       
        
        
        name_root_folder = output_dir + name_root_folder;
        File folder = new File(name_root_folder);
        if(!folder.exists()){
            folder.mkdirs();
        }
        String[] get_name = apkPath.split("/");
        
        //String name_folder = get_name[get_name.length - 1].split("\\.")[0];        
        String name_folder = get_name[get_name.length - 1].replace(".apk", "");
        
        output_dir = name_root_folder + "/" + name_folder;
        config.initSoot(apkPath,output_dir);
        if(DEBUG){
            System.out.println("Extracting the feature "+feature+" from "+apkPath);
        }

        Activity_extractor activity_extractor = new Activity_extractor();
        if (Feat_Type.equals("Activity")) {
            System.out.println("The searched feature is an Activity");
            ArrayList<String> dependencies = new ArrayList<>();
            if(!feature.startsWith(".")) {
                dependencies = activity_extractor.extract_activity_dependencies_PDG(new ArrayList<String>(), feature);
                System.out.println(dependencies.size());

            }else{
                if(DEBUG) {
                    System.out.println("DEBUG : Relative declaration of activity.\nTrying with soft dependencies check ..");
                }
                dependencies = activity_extractor.extract_activity_dependencies_PDG_soft(new ArrayList<String>(), feature);
                if(!dependencies.isEmpty()){
                    String correspondence ="";
                    for(String s : dependencies){
                        if(s.contains(feature) && !s.contains("$")){
                            correspondence= s +":"+feature;
                            if(Instrumenter.DEBUG) {
                                System.out.println("DEBUG : Real name "+s);
                            }
                            feature= s;
                            break;
                        }
                    }
                    config.WriteFile("Relative_features.txt",correspondence);

                }else{
                    System.out.println("No feature found :(((( ");
                }
            }
            ArrayList<My_slice> slices = activity_extractor.identify_startActivity(feature);
            System.out.println(slices.size());
            SootClass slice_class = null;
            if(!slices.isEmpty()) {
                if(Instrumenter.DEBUG) {
                    System.out.println("DEBUG : Slice extracted ! ");
                }
                My_slice simplest = config.get_simpler_slice(slices);
                config.WriteFile("class_of_extraction.txt", simplest.getFeature());
                simplest.setName("Slice" + name_folder);
                simplest.setFeature(feature);
                ArrayList<String> slice_dep = config.create_dependencies_file(simplest);
                dependencies.addAll(slice_dep);
                if(Instrumenter.DEBUG) {
                    System.out.println("Adding the slice "+simplest.getName()+"to the final Scene\n\n");
                }
                SootClass tmp = simplest.get_soot_class();
                if(Instrumenter.DEBUG) {
                    System.out.println(simplest.toString());
                }
                slice_class = tmp;
                slice_found=true;

            }else{
                System.out.println("Sorry, no slice found for the application "+name_folder);
            }
            activity_extractor.extract_classes(dependencies, apkPath);
            if(slice_class != null) {
                slice_class.setApplicationClass();
            }
        }else if (Feat_Type.equals("URL") || Feat_Type.equals("APICall") || Feat_Type.equals("APIPermission")){
            System.out.println("The searched feature is a " + Feat_Type);
            
            SootClass class_of_url = null;
            
            if (Feat_Type.equals("URL")) {
	            URL_extractor url_extractor = new URL_extractor();
	            class_of_url = url_extractor.extract_class_url(feature);
            }
            else if (Feat_Type.equals("APICall")) {
            	APICall_extractor api_call_extractor = new APICall_extractor();
	            class_of_url = api_call_extractor.extract_class_api_call(feature);
            }
            else if(Feat_Type.equals("APIPermission")) {
            	APIPermissions_extractor api_permissions_extractor = new APIPermissions_extractor();
	            class_of_url = api_permissions_extractor.extract_class_api_permission(feature);
            }            	
            
            
            ArrayList<String> dependencies_tot = new ArrayList<>();
            if(class_of_url!=null) {
                ArrayList<String> dependencies = activity_extractor.extract_activity_dependencies_PDG(new ArrayList<String>(), class_of_url.getName());
                dependencies_tot.addAll(dependencies);
            }else{
                System.out.println("Sorry the feature has failed to being identified in this apk ...\nExiting\n");
                exit(0);
            }
            if(Instrumenter.DEBUG) {
                System.out.println("Class containing the feature found : "+class_of_url.getName());
            }
            System.out.println("Trying to slice only the method invocation");
            CallGraphUtility cgUtil = new CallGraphUtility();
            
            ArrayList<SootMethod> targets = null;
            if (Feat_Type.equals("URL") || Feat_Type.equals("APIPermission")) {
            	targets = config.find_method_for_feature(class_of_url,feature);
            }
            else if (Feat_Type.equals("APICall")) {
            	targets = config.find_method_for_feature_api_call(class_of_url,feature);
            }            
            if(Instrumenter.DEBUG) {
                System.out.println("Possible targets" + targets);
            }
            boolean done= false;
            Iterator<SootMethod> target_iterator = targets.iterator();
            SootClass class_of_url_inner = null;
            SootClass slice_class = null;
            while(done== false && target_iterator.hasNext() ){
                SootMethod method = target_iterator.next();
                
                
                Map<SootClass,ArrayList<SootMethod>> result_method = cgUtil.get_callgraph_for_method(apkPath,jarsPath,class_of_url,method);
                
                              
                if(!result_method.isEmpty()){
                    class_of_url_inner = result_method.keySet().iterator().next();
                    System.out.println("Found calling class "+class_of_url_inner.getName()+", getting now the dependencies of it ...");
                    ArrayList<My_slice> slices = activity_extractor.extract_method_call_method(class_of_url_inner,result_method.get(class_of_url_inner).get(0),method);
                    if(!slices.isEmpty()) {
                    	My_slice simplest = new My_slice(null, null);
                    	try {
                    		simplest = config.get_simpler_slice(slices);                    		
                    	}
                    	catch(Exception e) {
                    		System.out.println(e);
                    		continue;
                    	}
                        
                        
                        simplest.setName("Slice" + name_folder+"method");
                        simplest.setFeature("tmp");
                        SootClass tmp = simplest.get_soot_class();
                        System.out.println(simplest.toString());
                        config.WriteFile("class_of_extraction.txt", class_of_url_inner.getName());
                        slice_class = tmp;
                        slice_found=true;
                        done = true;
                    }else{
                        System.out.println("No possible slice found :(");
                    }
                }else{
                    System.out.println("No possible slice found :(");
                }

           }
            
            if(slice_class != null) {
            	ArrayList<String> dependencies = activity_extractor.extract_activity_dependencies_PDG(new ArrayList<String>(), class_of_url_inner.getName());
                dependencies_tot.addAll(dependencies);	
            }
            
            Set<String> foo = new HashSet<String>(dependencies_tot);
            ArrayList<String> mainList = new ArrayList<String>();
            mainList.addAll(foo);
            activity_extractor.extract_classes(mainList, apkPath);
            if(slice_class != null){
                slice_class.setApplicationClass();
            }else{
                System.out.println("Sorry, it was not possible to retrieve the intended feature from this application :( ");
                File dir = new File(output_dir);
                if(dir.isDirectory() && dir.exists()){
                    try {
                        FileUtils.deleteDirectory(dir);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
                exit(0);
            }
        }
        Options.v().set_output_format(Instrumenter.output_format);
        Options.v().set_output_dir(output_dir);
        config.clean_final_export();
        if (new File(output_dir + "/classes.txt").exists()) {
            System.out.println("Now writing files into folder " + output_dir + " :) ");
            PackManager.v().writeOutput();
            if(slice_found){
                System.out.println("Dependencies exported and slice");
            }else{
                System.out.println("Dependencies exported but no slice");
            }
        }else {
            System.out.println("Sorry, it was not possible to retrieve the intended feature from this application :( ");
            File dir = new File(output_dir);
            if(dir.isDirectory() && dir.exists()){
                try {
                    FileUtils.deleteDirectory(dir);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }
        exit(0);
    }
}