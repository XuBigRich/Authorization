package cn.piao888.user.dto;

import lombok.Data;

import java.io.Serializable;
import java.math.BigDecimal;

/**
 * @Author: lidong
 * @Description 账户信息
 * @Date Created in 2019/1/13 16:39
 */
@Data
public class AccountDTO implements Serializable {

    private BigDecimal amount;

    public BigDecimal getAmount() {
        return amount;
    }

    public void setAmount(BigDecimal amount) {
        this.amount = amount;
    }
}
