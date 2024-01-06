package cn.piao888.user.vo.response;

import java.io.Serializable;

/**
 * @author: lidong
 * @date: 2018-07-03 16:55
 */
public class ObjectResponse<T> extends BaseResponse implements Serializable {

    private T data;

    public T getData() {
        return data;
    }

    public void setData(T data) {
        this.data = data;
    }

    public static ObjectResponse failed(Integer code, String msg) {
        ObjectResponse objectResponse = new ObjectResponse();
        objectResponse.setStatus(code);
        objectResponse.setMessage(msg);
        return objectResponse;
    }

    public static <T> ObjectResponse success(T data) {
        ObjectResponse objectResponse = new ObjectResponse();
        objectResponse.setStatus(200);
        objectResponse.setData(data);
        return objectResponse;
    }
}
