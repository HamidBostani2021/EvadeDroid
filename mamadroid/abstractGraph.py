''' 
info: This script first preprocesses the sequences of API calls and then abstracts them to the two different modes of operation 
i.e., package and family modes.
'''
import os
from multiprocessing import Process

def _preprocess_graph(app, _dir, db):
    ''' gets and clean the callers and callees'''

    appl = app.split("/")[-1]
    with open(appl, 'w') as fp:
        with open(app) as fh:
            for lines in fh:
                caller = ""
                callee = []
                line = lines.split(" ==> ")
                caller = line[0].split(":")[0].replace("<", "")
                if "," in str(line[1]):    # check if more than 1 callee exists
                    subc = line[1].split("\\n',")
                    for i in subc:
                        subCallees = i.split(":")
                        if "[" in subCallees[0]:
                            callee.append(subCallees[0].replace("['<", "").strip())
                        else:
                            callee.append(subCallees[0].replace("'<", "").strip())
                else:
                    callee.append(line[1].split(":")[0].replace("['<", "").strip())
                fp.write(caller + "\t")
                _length = len(callee)
                for a in range(_length):
                    if a < _length - 1:
                        fp.write(str(callee[a]).strip('"<') + "\t")
                    else:
                        fp.write(str(callee[a]).strip('"<') + "\n")
    selfDefined(appl, _dir, db)


def selfDefined(f, _dir, db):
    ''' calls all three modes of abstraction '''    
    
    Package = []
    Family = []
    Class = []
    with open(_dir + "/Packages.txt") as fh:
        for l in fh:
            if l.startswith('.'):
                Package.append(l.strip('\n').lstrip('.'))
            else:
                Package.append(l.strip('\n').strip())
    with open(_dir + "/Families.txt") as fh:
        print("Family - abstractGraph: " + str(os.getcwd()))
        for l in fh:
            Family.append(l.strip('\n').strip())
    with open(_dir + "/classes.txt") as fh:
        for l in fh:
            Class.append(l.strip('\n').strip())
    ff = abstractToClass(Class, f, _dir, db)
    os.remove(f)
    Package.reverse()
    
    abstractToMode(Family, ff, _dir, db)
    abstractToMode(Package, ff, _dir, db)
    
    #fam = Process(target = abstractToMode, args=(Family, ff, _dir))
    #fam.start()
    #pack = Process(target=abstractToMode, args=(Package, ff, _dir))
    #pack.start()
    #pack.join()



def _repeat_function(lines, P, fh, _sep):
    if lines.strip() in P:
        fh.write(lines.strip() + _sep)
    else:
        if "junit." in lines:
            return
        if '$' in lines:
            if lines.replace('$', '.') in P:
                fh.write(lines.replace('$', '.') + _sep)
                return
            elif lines.split('$')[0] in P:
                fh.write(lines.split('$')[0] + _sep)
                return
        items = lines.strip().split('.')
        item_len = len(items)
        count_l = 0
        for item in items:
            if len(item) < 3:
                count_l += 1
        if count_l > (item_len / 2):
            fh.write("obfuscated" + _sep)
        else:
            fh.write("self-defined" + _sep)


def abstractToClass(_class_whitelist, _app, _dir, db):
    ''' abstracts the API calls to classes '''

    newfile = _dir + "/class/" + db + '/'+_app.split('/')[-1]
    with open(newfile, 'w') as fh:
        with open(_app) as fp:
            for line in fp:
                lines = line.strip('\n').split('\t')
                lines = [jjj for jjj in lines if len(jjj) > 1] # ensures each caller or callee is not a single symbol e.g., $
                num = len(lines)
                for a in range(num):
                    if a < num - 1:
                        _repeat_function(lines[a], _class_whitelist, fh, "\t")
                    else:
                        _repeat_function(lines[a], _class_whitelist, fh, "\n")

    return newfile


def abstractToMode(_whitelist, _app, _dir, db):
    ''' abstracts the API calls to either package or family '''
    dico = {"org.xml": 'xml', "com.google":'google', "com.google.":'google', "javax.": 'javax', "java.": 'java', "org.w3c.dom": 'dom', "org.json": 'json', "org.apache": 'apache', "android.": 'android', "dalvik.": 'dalvik'}
    family = False
    if len(_whitelist) > 15:
        newfile = _dir + "/package/" + db + '/' + _app.split('/')[-1]
    else:
        newfile = _dir + "/family/" + db + '/' + _app.split('/')[-1]
        family = True

    i = 0
    with open(newfile, 'w') as fh:
        with open(_app) as fp:
            for line in fp:
                i += 1
                #print("i = " + str(i))
                #print(line)
                lines = line.strip('\n').split('\t')
                j = 0
                for items in lines:
                    j += 1
                    #print("j = " + str(j))
                    if "obfuscated" in items or "self-defined" in items:
                        fh.write(items + '\t')
                    else:
                        k = 0
                        for ab in _whitelist:
                            k += 1
                            #print("k = " + str(k))
                            if i == 20 and j == 3 and k == 1:
                                print("test")
                            if items.startswith(ab):
                                if family: # if True, family, otherwise, package
                                    fh.write(dico[ab] + '\t')
                                else:
                                    fh.write(ab + '\t')
                                break
                fh.write('\n')
    print("Finish")
