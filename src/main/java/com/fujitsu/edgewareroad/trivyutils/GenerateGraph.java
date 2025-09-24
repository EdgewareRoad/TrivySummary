package com.fujitsu.edgewareroad.trivyutils;

import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.RenderingHints;
import java.awt.geom.AffineTransform;
import java.io.StringWriter;
import java.io.Writer;
import java.lang.Math;
import java.util.ArrayList;
import java.util.Collections;

import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.batik.anim.dom.SVGDOMImplementation;
import org.apache.batik.svggen.SVGGraphics2D;
import org.w3c.dom.DOMImplementation;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import com.fujitsu.edgewareroad.trivysummary.TrivySummary;
import com.fujitsu.edgewareroad.trivyutils.dto.prioritymodel.PriorityModel;
import com.fujitsu.edgewareroad.trivyutils.dto.prioritymodel.PriorityModelType;
import com.fujitsu.edgewareroad.trivyutils.dto.prioritymodel.VulnerabilityPriority;
import com.fujitsu.edgewareroad.trivyutils.dto.prioritymodel.VulnerabilityScorePriorityThresholds;
import com.fujitsu.edgewareroad.trivyutils.dto.trivyscan.TrivyScanVulnerabilities;
import com.fujitsu.edgewareroad.trivyutils.dto.trivyscan.TrivyScanVulnerability;

public class GenerateGraph {
    public static String GetSVG(TrivyScanVulnerabilities vulnerabilities, TrivySummary.Configuration configuration) {
        // Get a DOMImplementation.
        DOMImplementation domImpl = SVGDOMImplementation.getDOMImplementation();

        // Create an instance of org.w3c.dom.Document.
        String svgNS = SVGDOMImplementation.SVG_NAMESPACE_URI;
        Document document = domImpl.createDocument(svgNS, "svg", null);

        Element circle = document.createElementNS(SVGDOMImplementation.SVG_NAMESPACE_URI, "circle");
        circle.setAttributeNS(null, "cx", "50");
        circle.setAttributeNS(null, "cy", "100");
        circle.setAttributeNS(null, "r", "10");

        Element anchor = document.createElementNS(SVGDOMImplementation.SVG_NAMESPACE_URI, "a");
        anchor.setAttributeNS(null, "href", "http://ulcc.org.uk");
        anchor.appendChild(circle);

        document.getDocumentElement().appendChild(anchor);
        document.getDocumentElement().appendChild(circle);

        // Create an instance of the SVG Generator.
        SVGGraphics2D svgGenerator = new SVGGraphics2D(document);
        svgGenerator.setSVGCanvasSize(new Dimension(650, 500));

        // Ask the test to render into the SVG Graphics2D implementation.
        GenerateGraph graph = new GenerateGraph();
        graph.paint(svgGenerator, document, vulnerabilities, configuration);

        // Finally, stream out SVG to the standard output using
        // UTF-8 encoding.
        try (Writer buffer = new StringWriter();) {
            TransformerFactory transFactory = TransformerFactory.newInstance();
            Transformer transformer = transFactory.newTransformer();
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
            transformer.transform(new DOMSource(svgGenerator.getRoot()), new StreamResult(buffer));
            String output = buffer.toString();
            return output;
        } catch (Exception e) {
            return null;
        }
    }

    private double getEPSSYValue(double lpssValue, int lpssMode) {
        if (lpssMode <= 1)
            return lpssValue;
        double retVal = Math.pow(lpssValue, 1.0d / lpssMode);
        return retVal;
    }

    public static final VulnerabilityScorePriorityThresholds DEFAULT_FLOOR_VALUES_FOR_CVE_LABELS = new VulnerabilityScorePriorityThresholds(2.0, 0.05);

    private boolean showCVELabel(TrivyScanVulnerability vulnerability, PriorityModel priorityModel,
            VulnerabilityPriority showLabelThreshold) {
        if (priorityModel == null || priorityModel.getType().equals(PriorityModelType.SEVERITYONLY))
        {
            return vulnerability.getCvssScore() >= DEFAULT_FLOOR_VALUES_FOR_CVE_LABELS.getMinimumCvss() && vulnerability.getEpssScoreNormalised() >= DEFAULT_FLOOR_VALUES_FOR_CVE_LABELS.getMinimumEpss();
        }
        else
        {
            if (showLabelThreshold == null) {
                showLabelThreshold = VulnerabilityPriority.MEDIUM;
            }

            return vulnerability.getPriority().ordinal() >= showLabelThreshold.ordinal();
        }
    }

    private void paint(SVGGraphics2D svgGenerator, Document document, TrivyScanVulnerabilities vulnerabilities,
            TrivySummary.Configuration configuration) {
        Dimension canvasSize = svgGenerator.getSVGCanvasSize();
        final int GRAPH_OFFSET = 30;
        // Note that we can't inverse square scale the EPSS axis in ELLIPTICAL mode as
        // the ellipse will look very very weird or, worse, not match the calculated
        // value
        final int EPSS_MODE = configuration.getPriorityModel() != null && configuration.getPriorityModel().getType().equals(PriorityModelType.ELLIPTICAL) ? 1
                : 2;
        final int DOT_RADIUS = 3;
        int graphWidth = (int) canvasSize.getWidth() - GRAPH_OFFSET;
        int graphHeight = (int) canvasSize.getHeight() - GRAPH_OFFSET;
        AffineTransform defaultTransform = svgGenerator.getTransform();
        FontMetrics fontMetrics = svgGenerator.getFontMetrics();

        svgGenerator.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);

        // Graph axes and labels, plus background shading if prioritisation is being
        // used.

        svgGenerator.setPaint(Color.BLACK);
        svgGenerator.drawString("CVSS", GRAPH_OFFSET, graphHeight + GRAPH_OFFSET);
        AffineTransform transformGraph = AffineTransform.getQuadrantRotateInstance(3);
        transformGraph.translate(-graphHeight, GRAPH_OFFSET);
        svgGenerator.setTransform(transformGraph);
        svgGenerator.drawString("EPSS", 0, -(GRAPH_OFFSET * 2 / 3));

        if (configuration.getPriorityModel() != null && configuration.getPriorityModel().getType() == PriorityModelType.ELLIPTICAL) {
            VulnerabilityScorePriorityThresholds thresholds;
            svgGenerator.setPaint(Color.decode("#f0fff0"));
            svgGenerator.fillRect(0, 0, graphHeight, graphWidth);

            thresholds = configuration.getPriorityModel().getThresholds(VulnerabilityPriority.MEDIUM);
            if (thresholds != null) {
                svgGenerator.setPaint(Color.decode("#fff0b0"));
                int epssAxis = Double
                        .valueOf(graphHeight * (1.0 - getEPSSYValue(thresholds.getMinimumEpss(), EPSS_MODE)))
                        .intValue();
                int cvssAxis = Double.valueOf(graphWidth * (10.0 - thresholds.getMinimumCvss()) / 10.0).intValue();
                svgGenerator.fillOval(graphHeight - epssAxis, graphWidth - cvssAxis, epssAxis * 2, cvssAxis * 2);
            }
            thresholds = configuration.getPriorityModel().getThresholds(VulnerabilityPriority.HIGH);
            if (thresholds != null) {
                svgGenerator.setPaint(Color.decode("#ffe0e0"));
                int epssAxis = Double
                        .valueOf(graphHeight * (1.0 - getEPSSYValue(thresholds.getMinimumEpss(), EPSS_MODE)))
                        .intValue();
                int cvssAxis = Double.valueOf(graphWidth * (10.0 - thresholds.getMinimumCvss()) / 10.0).intValue();
                svgGenerator.fillOval(graphHeight - epssAxis, graphWidth - cvssAxis, epssAxis * 2, cvssAxis * 2);
            }
            thresholds = configuration.getPriorityModel().getThresholds(VulnerabilityPriority.CRITICAL);
            if (thresholds != null) {
                svgGenerator.setPaint(Color.decode("#f0b0b0"));
                int epssAxis = Double
                        .valueOf(graphHeight * (1.0 - getEPSSYValue(thresholds.getMinimumEpss(), EPSS_MODE)))
                        .intValue();
                int cvssAxis = Double.valueOf(graphWidth * (10.0 - thresholds.getMinimumCvss()) / 10.0).intValue();
                svgGenerator.fillOval(graphHeight - epssAxis, graphWidth - cvssAxis, epssAxis * 2, cvssAxis * 2);
            }
            svgGenerator.setPaint(Color.BLACK);
        } else if (configuration.getPriorityModel() != null && configuration.getPriorityModel().getType() == PriorityModelType.RECTANGULAR) {
            VulnerabilityScorePriorityThresholds thresholds;
            svgGenerator.setPaint(Color.decode("#f0fff0"));
            svgGenerator.fillRect(0, 0, graphHeight, graphWidth);

            thresholds = configuration.getPriorityModel().getThresholds(VulnerabilityPriority.MEDIUM);
            if (thresholds != null) {
                svgGenerator.setPaint(Color.decode("#fff0b0"));
                int epssAxis = Double
                        .valueOf(graphHeight * (1.0 - getEPSSYValue(thresholds.getMinimumEpss(), EPSS_MODE)))
                        .intValue();
                int cvssAxis = Double.valueOf(graphWidth * (10.0 - thresholds.getMinimumCvss()) / 10.0).intValue();
                svgGenerator.fillRect(graphHeight - epssAxis, graphWidth - cvssAxis, epssAxis, cvssAxis);
            }
            thresholds = configuration.getPriorityModel().getThresholds(VulnerabilityPriority.HIGH);
            if (thresholds != null) {
                svgGenerator.setPaint(Color.decode("#ffe0e0"));
                int epssAxis = Double
                        .valueOf(graphHeight * (1.0 - getEPSSYValue(thresholds.getMinimumEpss(), EPSS_MODE)))
                        .intValue();
                int cvssAxis = Double.valueOf(graphWidth * (10.0 - thresholds.getMinimumCvss()) / 10.0).intValue();
                svgGenerator.fillRect(graphHeight - epssAxis, graphWidth - cvssAxis, epssAxis, cvssAxis);
            }
            thresholds = configuration.getPriorityModel().getThresholds(VulnerabilityPriority.CRITICAL);
            if (thresholds != null) {
                svgGenerator.setPaint(Color.decode("#f0b0b0"));
                int epssAxis = Double
                        .valueOf(graphHeight * (1.0 - getEPSSYValue(thresholds.getMinimumEpss(), EPSS_MODE)))
                        .intValue();
                int cvssAxis = Double.valueOf(graphWidth * (10.0 - thresholds.getMinimumCvss()) / 10.0).intValue();
                svgGenerator.fillRect(graphHeight - epssAxis, graphWidth - cvssAxis, epssAxis, cvssAxis);
            }
            svgGenerator.setPaint(Color.BLACK);
        }

        // Now draw the axes
        svgGenerator.drawLine(0, 0, 0, graphWidth);
        svgGenerator.drawLine(0, 0, graphHeight, 0);
        // Now draw the 10 ticks on each axis
        for (int tick = 0; tick <= 10; tick++) {
            svgGenerator.drawLine(0, tick * graphWidth / 10, -(GRAPH_OFFSET / 6), tick * graphWidth / 10);
            // Each tick is equal to an LPSS value of (10 - tick)/10
            double lpssModdedValue = getEPSSYValue(Double.valueOf(10 - tick) / 10, EPSS_MODE);
            int tickYValue = Double.valueOf(lpssModdedValue * graphHeight).intValue();
            svgGenerator.drawLine(tickYValue, 0, tickYValue, -(GRAPH_OFFSET / 6));
        }
        svgGenerator.setTransform(defaultTransform);
        Font fontDefault = svgGenerator.getFont();
        Font fontDigits = fontDefault.deriveFont(Float.valueOf(fontDefault.getSize()) - 3);
        svgGenerator.setFont(fontDigits);
        fontMetrics = svgGenerator.getFontMetrics(fontDigits);
        for (int tick = 1; tick <= 10; tick++) {
            String cvssScore = String.valueOf(tick);
            svgGenerator.drawString(cvssScore,
                    GRAPH_OFFSET - fontMetrics.stringWidth(cvssScore) + (tick * graphWidth / 10),
                    graphHeight + (GRAPH_OFFSET / 6) + fontMetrics.getHeight());

            double epssValue = Double.valueOf(11 - tick) / 10;
            String epssScore = String.valueOf(epssValue);
            double epssModdedValue = getEPSSYValue(epssValue, EPSS_MODE);
            int tickYValue = graphHeight - Double.valueOf(epssModdedValue * graphHeight).intValue();
            svgGenerator.drawString(epssScore, GRAPH_OFFSET - fontMetrics.stringWidth(epssScore) - (GRAPH_OFFSET / 6),
                    tickYValue + fontMetrics.getHeight());
        }

        if (vulnerabilities != null) {
            // We process the vulnerabilities in reverse so that the higher priority ones
            // appear on top in Z-order
            var vulnArray = new ArrayList<>(vulnerabilities);
            Collections.reverse(vulnArray);

            for (TrivyScanVulnerability vulnerability : vulnArray) {
                switch (vulnerability.getPriority()) {
                    case CRITICAL:
                        svgGenerator.setPaint(Color.RED.darker().darker());
                        break;

                    case HIGH:
                        svgGenerator.setPaint(Color.RED);
                        break;

                    case MEDIUM:
                        svgGenerator.setPaint(Color.ORANGE);
                        break;

                    case LOW:
                        svgGenerator.setPaint(Color.GREEN);
                        break;

                    default:
                        svgGenerator.setPaint(Color.DARK_GRAY);
                        break;
                }

                Double xPos = GRAPH_OFFSET + (vulnerability.getCvssScore() * graphWidth / 10);
                Double yPos = (1 - getEPSSYValue(vulnerability.getEpssScoreNormalised(), EPSS_MODE)) * graphHeight;
                svgGenerator.fillOval(xPos.intValue() - DOT_RADIUS, yPos.intValue() - DOT_RADIUS, DOT_RADIUS * 2,
                        DOT_RADIUS * 2);
                if (showCVELabel(vulnerability, configuration.getPriorityModel(), configuration.getFailPriorityThreshold())) {
                    // We try to label the dot too
                    svgGenerator.setPaint(Color.BLACK);
                    svgGenerator.drawString(vulnerability.getVulnerabilityID(),
                            xPos.intValue() - DOT_RADIUS - fontMetrics.stringWidth(vulnerability.getVulnerabilityID()),
                            yPos.intValue() + (fontMetrics.getHeight() / 3));
                }
            }
        }
    }
}
