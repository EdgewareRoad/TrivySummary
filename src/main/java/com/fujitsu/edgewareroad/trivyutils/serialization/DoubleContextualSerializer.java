package com.fujitsu.edgewareroad.trivyutils.serialization;

import java.math.BigDecimal;
import java.math.RoundingMode;

import tools.jackson.core.JacksonException;
import tools.jackson.core.JsonGenerator;
import tools.jackson.databind.BeanProperty;
import tools.jackson.databind.SerializationContext;
import tools.jackson.databind.ValueSerializer;

public class DoubleContextualSerializer extends ValueSerializer<Double> {

    private int precision = 0;

    public DoubleContextualSerializer(int precision) {
        this.precision = precision;
    }

    public DoubleContextualSerializer() {}

    @Override
    public ValueSerializer<?> createContextual(SerializationContext ctxt, BeanProperty property) {
        Precision precisionAnnotation = property.getAnnotation(Precision.class);
        if (precisionAnnotation != null) {
            return new DoubleContextualSerializer(precisionAnnotation.precision());
        }
        return this;
    }

    @Override
    public void serialize(Double value, JsonGenerator gen, SerializationContext ctxt) throws JacksonException {
        if (precision == 0) {
            gen.writeNumber(value.doubleValue());
        }
        else {
            BigDecimal bd = new BigDecimal(value);
            bd = bd.setScale(precision, RoundingMode.HALF_UP);
            gen.writeString(bd.toPlainString());
        }
    }
}
