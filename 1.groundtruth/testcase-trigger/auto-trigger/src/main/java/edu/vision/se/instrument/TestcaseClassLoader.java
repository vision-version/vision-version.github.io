package edu.vision.se.instrument;

import javassist.CannotCompileException;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.NotFoundException;
import lombok.extern.slf4j.Slf4j;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.lang.instrument.ClassFileTransformer;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.List;

@Slf4j
public class TestcaseClassLoader extends URLClassLoader {

    public static final String STATE_TABLE_CLASS_NAME = "edu.vision.se.instrument.state.GlobalStateTable";
    public static final String STATE_TABLE_INTERNAL_NAME = "edu/vision/se/instrument/state/GlobalStateTable";
    public static final String STATE_NODE_CLASS_NAME = "edu.vision.se.instrument.state.StateNode";
    public static final String STATE_NODE_INTERNAL_NAME = "edu/vision/se/instrument/state/StateNode";
    public static final String ADD_STATE_NODE_METHOD_NAME = "addStateNode";

    private static final byte[] STATE_TABLE_BYTES;

    private static final byte[] STATE_NODE_BYTES;

    private ClassFileTransformer transformer = new SnoopTestcaseTransformer();

    static {
        ClassPool classPool = ClassPool.getDefault();
        try {
            CtClass tableClass = classPool.get(STATE_TABLE_CLASS_NAME);
            STATE_TABLE_BYTES = tableClass.toBytecode();

            CtClass nodeClass = classPool.get(STATE_NODE_CLASS_NAME);
            STATE_NODE_BYTES = nodeClass.toBytecode();
        } catch (NotFoundException | IOException | CannotCompileException e) {
            throw new RuntimeException(e);
        }
    }

    public TestcaseClassLoader(List<String> pathList) throws MalformedURLException {
        super(stringsToUrls(pathList.toArray(new String[0])), ClassLoader.getSystemClassLoader().getParent()); // 打破双亲委派，跳过Application ClassLoader
    }

    private static URL[] stringsToUrls(String[] paths) throws MalformedURLException {
        URL[] urls = new URL[paths.length];
        for (int i = 0; i < paths.length; i++) {
            urls[i] = new File(paths[i]).toURI().toURL();
        }
        return urls;
    }

    @Override
    protected Class<?> findClass(String name) throws ClassNotFoundException {
        if(name == null) return null;
        if(name.startsWith("org.junit") || name.startsWith("junit")) { // junit包 通过 Application ClassLoader加载
            return ClassLoader.getSystemClassLoader().loadClass(name);
        }

        if (STATE_TABLE_CLASS_NAME.equals(name)) {
            return defineClass(name, STATE_TABLE_BYTES, 0, STATE_TABLE_BYTES.length);
        } else if (STATE_NODE_CLASS_NAME.equals(name)) {
            return defineClass(name, STATE_NODE_BYTES, 0, STATE_NODE_BYTES.length);
        } else {
            String internalName = name.replace('.', '/');
            String path = internalName.concat(".class");
            byte[] originalBytecode;
            try (InputStream in = super.getResourceAsStream(path)) {
                if (in == null) {
                    throw new ClassNotFoundException("Cannot find class " + name);
                }
                originalBytecode = in.readAllBytes();
            } catch (IOException e) {
                throw new ClassNotFoundException("I/O exception while loading class.", e);
            }
            assert (originalBytecode != null);

//            byte[] bytesToLoad;
//            try {
//                byte[] instrumented = transformer.transform(this, internalName, null, null, originalBytecode);
//                if (instrumented != null) {
//                    bytesToLoad = instrumented;
//                } else {
//                    bytesToLoad = originalBytecode;
//                }
//            } catch (IllegalClassFormatException e) {
//                bytesToLoad = originalBytecode;
//            }
            return defineClass(name, originalBytecode, 0, originalBytecode.length);
        }
    }

}
