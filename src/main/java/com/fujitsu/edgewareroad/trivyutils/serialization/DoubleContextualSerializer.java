package com.fujitsu.edgewareroad.trivyutils.serialization;

import java.io.IOException;
import java.math.BigDecimal;
import java.math.RoundingMode;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.BeanProperty;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.ContextualSerializer;

public class DoubleContextualSerializer extends JsonSerializer<Double> implements ContextualSerializer {

    private int precision = 0;

    public DoubleContextualSerializer(int precision) {
        this.precision = precision;
    }

    public DoubleContextualSerializer() {}

    @Override
    public void serialize(Double value, JsonGenerator gen, SerializerProvider serializers) throws IOException {
        if (precision == 0) {
            gen.writeNumber(value.doubleValue());
        }
        else {
            BigDecimal bd = new BigDecimal(value);
            bd = bd.setScale(precision, RoundingMode.HALF_UP);
            gen.writeString(bd.toPlainString());
        }
    }

    @Override
    public JsonSerializer<?> createContextual(SerializerProvider prov, BeanProperty property)
            throws JsonMappingException {
        Precision precisionAnnotation = property.getAnnotation(Precision.class);
        if (precisionAnnotation != null) {
            return new DoubleContextualSerializer(precisionAnnotation.precision());
        }
        return this;
    }
}
