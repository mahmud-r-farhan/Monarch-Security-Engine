'use client'

import React, { useState, useRef, useEffect } from 'react';
import { Stage, Layer, Image as KonvaImage, Text, Line, Transformer } from 'react-konva';
import Konva from 'konva';
import { toast } from 'sonner';
import { driver } from "driver.js";
import "driver.js/dist/driver.css";
import Toolbar from './Toolbar';
import Sidebar, { LayerItem } from './Sidebar';
import Header from './Header';
import { useTranslation } from 'react-i18next';

export interface LineItem {
  id?: string;
  tool: string;
  points: number[];
  color: string;
  strokeWidth: number;
}

export interface TextItem {
  id: string;
  x: number;
  y: number;
  text: string;
  fontSize: number;
  fill: string;
}

export interface CanvasState {
  layers: LayerItem[];
  lines: LineItem[];
  texts: TextItem[];
}

const ImageEditor: React.FC = () => {
  const [tool, setTool] = useState<string>('select');
  const [layers, setLayers] = useState<LayerItem[]>([]);
  const [isDarkMode, setIsDarkMode] = useState<boolean>(false);
  const [colorFormat, setColorFormat] = useState<string>('RGB');
  const [language, setLanguage] = useState<string>('en');
  const [canvasSize, setCanvasSize] = useState<{ width: number; height: number }>({ width: 800, height: 600 });
  const [selectedColor, setSelectedColor] = useState<string>('#000000');
  const [textInput, setTextInput] = useState<string>('Sample Text');
  const [fontSize, setFontSize] = useState<number>(24);
  const [brushSize, setBrushSize] = useState<number>(5);
  const [lines, setLines] = useState<LineItem[]>([]);
  const [texts, setTexts] = useState<TextItem[]>([]);
  const [isDrawing, setIsDrawing] = useState<boolean>(false);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  // History state for undo/redo
  const [history, setHistory] = useState<CanvasState[]>([
    { layers: [], lines: [], texts: [] }
  ]);
  const [historyIndex, setHistoryIndex] = useState<number>(0);

  const stageRef = useRef<Konva.Stage | null>(null);
  const transformerRef = useRef<Konva.Transformer | null>(null);
  const { t } = useTranslation();

  const recordState = (newLayers: LayerItem[], newLines: LineItem[], newTexts: TextItem[]) => {
    const nextState: CanvasState = {
      layers: newLayers,
      lines: newLines,
      texts: newTexts
    };
    const newHistory = history.slice(0, historyIndex + 1);
    newHistory.push(nextState);
    setHistory(newHistory);
    setHistoryIndex(newHistory.length - 1);
  };

  const handleUndo = () => {
    if (historyIndex > 0) {
      const prevIndex = historyIndex - 1;
      const state = history[prevIndex];
      setLayers(state.layers);
      setLines(state.lines);
      setTexts(state.texts);
      setHistoryIndex(prevIndex);
      setSelectedId(null);
      toast.info('Undo');
    }
  };

  const handleRedo = () => {
    if (historyIndex < history.length - 1) {
      const nextIndex = historyIndex + 1;
      const state = history[nextIndex];
      setLayers(state.layers);
      setLines(state.lines);
      setTexts(state.texts);
      setHistoryIndex(nextIndex);
      setSelectedId(null);
      toast.info('Redo');
    }
  };

  // Connect Konva Transformer to selected object
  useEffect(() => {
    if (selectedId && transformerRef.current && stageRef.current) {
      const selectedNode = stageRef.current.findOne('#' + selectedId);
      if (selectedNode) {
        transformerRef.current.nodes([selectedNode]);
        transformerRef.current.getLayer()?.batchDraw();
      } else {
        transformerRef.current.nodes([]);
      }
    } else if (transformerRef.current) {
      transformerRef.current.nodes([]);
    }
  }, [selectedId, texts]);

  // Keyboard shortcuts (Undo/Redo & Delete)
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      // Don't trigger if user is typing in an input/textarea
      if (['INPUT', 'TEXTAREA', 'SELECT'].includes((e.target as HTMLElement)?.tagName)) {
        return;
      }
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'z') {
        if (e.shiftKey) {
          handleRedo();
        } else {
          handleUndo();
        }
      } else if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'y') {
        handleRedo();
      } else if (e.key === 'Delete' || e.key === 'Backspace') {
        if (selectedId) {
          const updatedTexts = texts.filter((tItem) => tItem.id !== selectedId);
          if (updatedTexts.length !== texts.length) {
            setTexts(updatedTexts);
            recordState(layers, lines, updatedTexts);
            setSelectedId(null);
            toast.info('Deleted selected element');
          }
        }
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [historyIndex, history, selectedId, texts, layers, lines]);

  useEffect(() => {
    startTour();
  }, []);

  const startTour = () => {
    try {
      const driverObj = driver({
        showProgress: true,
        steps: [
          { element: '#toolbar', popover: { title: t('toolbar.title', 'Toolbar'), description: t('toolbar.description', 'Select editing tools here.') } },
          { element: '#canvas', popover: { title: t('canvas.title', 'Canvas'), description: t('canvas.description', 'Interactive editing area.') } },
          { element: '#sidebar', popover: { title: t('sidebar.title', 'Sidebar'), description: t('sidebar.description', 'Adjust layers, colors, and properties.') } },
        ]
      });
      driverObj.drive();
    } catch {
      // Driver tour optional fallback
    }
  };

  const handleToolChange = (newTool: string) => {
    setTool(newTool);
    if (newTool === 'text') {
      const newText: TextItem = {
        id: `text-${Date.now()}`,
        x: canvasSize.width / 4,
        y: canvasSize.height / 4,
        text: textInput || 'Sample Text',
        fontSize,
        fill: selectedColor,
      };
      const updatedTexts = [...texts, newText];
      setTexts(updatedTexts);
      setSelectedId(newText.id);
      recordState(layers, lines, updatedTexts);
    }
    toast.success(t('toolSelected', { tool: newTool }));
  };

  const handleLayerChange = (newLayers: LayerItem[]) => {
    setLayers(newLayers);
    recordState(newLayers, lines, texts);
  };

  const handleExport = () => {
    if (stageRef.current) {
      // Temporarily deselect for export
      setSelectedId(null);
      setTimeout(() => {
        if (stageRef.current) {
          const uri = stageRef.current.toDataURL();
          const link = document.createElement('a');
          link.download = 'image.png';
          link.href = uri;
          document.body.appendChild(link);
          link.click();
          document.body.removeChild(link);
          toast.success(t('exportSuccess', 'Image exported successfully!'));
        }
      }, 50);
    }
  };

  const handleImageUpload = (file: File) => {
    const reader = new FileReader();
    reader.onload = (e) => {
      const result = e.target?.result;
      if (typeof result === 'string') {
        const img = new window.Image();
        img.src = result;
        img.onload = () => {
          const width = img.width > 0 ? img.width : 800;
          const height = img.height > 0 ? img.height : 600;
          setCanvasSize({ width, height });
          const newLayers: LayerItem[] = [{ id: `layer-${Date.now()}`, visible: true, name: file.name || 'Image', image: img }];
          setLayers(newLayers);
          recordState(newLayers, lines, texts);
        };
      }
    };
    reader.readAsDataURL(file);
  };

  const handleNewCanvas = (width: number, height: number) => {
    setCanvasSize({ width, height });
    setLayers([]);
    setLines([]);
    setTexts([]);
    setSelectedId(null);
    recordState([], [], []);
  };

  const handleMouseDown = (e: Konva.KonvaEventObject<MouseEvent>) => {
    if (tool === 'draw' || tool === 'eraser') {
      setIsDrawing(true);
      const stage = e.target.getStage();
      const pos = stage?.getPointerPosition();
      if (pos) {
        const newLine: LineItem = {
          id: `line-${Date.now()}`,
          tool,
          points: [pos.x, pos.y],
          color: selectedColor,
          strokeWidth: brushSize
        };
        const updatedLines = [...lines, newLine];
        setLines(updatedLines);
      }
    } else if (tool === 'select' || tool === 'move') {
      const clickedOnEmpty = e.target === e.target.getStage();
      if (clickedOnEmpty) {
        setSelectedId(null);
      }
    }
  };

  const handleMouseMove = (e: Konva.KonvaEventObject<MouseEvent>) => {
    if (!isDrawing) return;

    const stage = e.target.getStage();
    const point = stage?.getPointerPosition();
    if (!point || lines.length === 0) return;

    const lastLine = { ...lines[lines.length - 1] };
    lastLine.points = lastLine.points.concat([point.x, point.y]);

    const updatedLines = lines.slice(0, lines.length - 1).concat(lastLine);
    setLines(updatedLines);
  };

  const handleMouseUp = () => {
    if (isDrawing) {
      setIsDrawing(false);
      recordState(layers, lines, texts);
    }
  };

  const handleTextDblClick = (e: Konva.KonvaEventObject<MouseEvent>, id: string) => {
    const textNode = e.target as Konva.Text;
    textNode.hide();

    const textPosition = textNode.absolutePosition();
    const stageContainer = stageRef.current?.container();
    const containerRect = stageContainer ? stageContainer.getBoundingClientRect() : { top: 0, left: 0 };

    const textarea = document.createElement('textarea');
    document.body.appendChild(textarea);

    textarea.value = textNode.text();
    textarea.style.position = 'absolute';
    textarea.style.top = `${containerRect.top + textPosition.y}px`;
    textarea.style.left = `${containerRect.left + textPosition.x}px`;
    textarea.style.width = `${textNode.width() + 20}px`;
    textarea.style.height = `${textNode.height() + 20}px`;
    textarea.style.fontSize = `${textNode.fontSize()}px`;
    textarea.style.border = '1px solid #000';
    textarea.style.padding = '4px';
    textarea.style.margin = '0px';
    textarea.style.overflow = 'hidden';
    textarea.style.background = 'white';
    textarea.style.outline = 'none';
    textarea.style.resize = 'none';
    textarea.style.lineHeight = textNode.lineHeight().toString();
    textarea.style.fontFamily = textNode.fontFamily();
    textarea.style.transformOrigin = 'left top';
    textarea.style.textAlign = textNode.align();
    textarea.style.color = textNode.fill() as string;
    textarea.style.zIndex = '1000';

    textarea.focus();

    const handleTextSave = () => {
      const newTextVal = textarea.value;
      if (document.body.contains(textarea)) {
        document.body.removeChild(textarea);
      }
      textNode.show();
      const updatedTexts = texts.map((tItem) => tItem.id === id ? { ...tItem, text: newTextVal } : tItem);
      setTexts(updatedTexts);
      recordState(layers, lines, updatedTexts);
    };

    textarea.addEventListener('keydown', function (evt) {
      if (evt.key === 'Enter' && !evt.shiftKey) {
        handleTextSave();
      }
    });

    textarea.addEventListener('blur', function () {
      handleTextSave();
    });
  };

  return (
    <div className={`flex flex-col h-screen ${isDarkMode ? 'dark' : ''}`}>
      <Header
        onImageUpload={handleImageUpload}
        onExport={handleExport}
        isDarkMode={isDarkMode}
        setIsDarkMode={setIsDarkMode}
        colorFormat={colorFormat}
        setColorFormat={setColorFormat}
        language={language}
        setLanguage={setLanguage}
        onNewCanvas={handleNewCanvas}
      />
      <div className="flex flex-1 overflow-hidden">
        <Toolbar
          onToolChange={handleToolChange}
          activeTool={tool}
          onUndo={handleUndo}
          onRedo={handleRedo}
          canUndo={historyIndex > 0}
          canRedo={historyIndex < history.length - 1}
        />
        <main className="flex-1 overflow-auto p-4 flex justify-center items-center bg-gray-100 dark:bg-gray-900">
          <div id="canvas" className="bg-white dark:bg-gray-800 rounded-lg shadow-xl p-4 max-w-full max-h-full overflow-auto">
            <Stage
              width={canvasSize.width}
              height={canvasSize.height}
              ref={stageRef}
              onMouseDown={handleMouseDown}
              onMouseMove={handleMouseMove}
              onMouseUp={handleMouseUp}
            >
              <Layer>
                {layers.map((layer) => (
                  layer.visible && layer.image && (
                    <KonvaImage
                      key={layer.id}
                      image={layer.image}
                      width={canvasSize.width}
                      height={canvasSize.height}
                    />
                  )
                ))}
                {lines.map((line, i) => (
                  <Line
                    key={line.id || i}
                    points={line.points}
                    stroke={line.color}
                    strokeWidth={line.strokeWidth || 5}
                    tension={0.5}
                    lineCap="round"
                    lineJoin="round"
                    globalCompositeOperation={
                      line.tool === 'eraser' ? 'destination-out' : 'source-over'
                    }
                  />
                ))}
                {texts.map((textItem) => (
                  <Text
                    key={textItem.id}
                    id={textItem.id}
                    x={textItem.x}
                    y={textItem.y}
                    text={textItem.text}
                    fontSize={textItem.fontSize}
                    fill={textItem.fill}
                    draggable={tool === 'select' || tool === 'move'}
                    onClick={() => setSelectedId(textItem.id)}
                    onDragEnd={(e) => {
                      const updatedTexts = texts.map((tItem) =>
                        tItem.id === textItem.id ? { ...tItem, x: e.target.x(), y: e.target.y() } : tItem
                      );
                      setTexts(updatedTexts);
                      recordState(layers, lines, updatedTexts);
                    }}
                    onDblClick={(e) => handleTextDblClick(e, textItem.id)}
                  />
                ))}
                {selectedId && (
                  <Transformer
                    ref={transformerRef}
                    boundBoxFunc={(oldBox, newBox) => {
                      if (newBox.width < 10 || newBox.height < 10) {
                        return oldBox;
                      }
                      return newBox;
                    }}
                  />
                )}
              </Layer>
            </Stage>
          </div>
        </main>
        <Sidebar
          layers={layers}
          onLayerChange={handleLayerChange}
          colorFormat={colorFormat}
          selectedColor={selectedColor}
          setSelectedColor={setSelectedColor}
          textInput={textInput}
          setTextInput={setTextInput}
          fontSize={fontSize}
          setFontSize={setFontSize}
          brushSize={brushSize}
          setBrushSize={setBrushSize}
          activeTool={tool}
        />
      </div>
    </div>
  );
};

export default ImageEditor;
