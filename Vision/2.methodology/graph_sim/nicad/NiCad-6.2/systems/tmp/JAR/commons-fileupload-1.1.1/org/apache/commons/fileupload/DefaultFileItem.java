package org.apache.commons.fileupload;

import java.io.File;
import org.apache.commons.fileupload.disk.DiskFileItem;

public class DefaultFileItem extends DiskFileItem {
  public DefaultFileItem(String fieldName, String contentType, boolean isFormField, String fileName, int sizeThreshold, File repository) {
    super(fieldName, contentType, isFormField, fileName, sizeThreshold, repository);
  }
}
