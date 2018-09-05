#include "vb_components.h"
#include <sstream>

#define EVENTS(...) __VA_ARGS__
#define COMPONENT_VAR(n) c ## _ ## n
#define DECLARE_COMPONENT(g, n, e) Component COMPONENT_VAR(n); \
                                   COMPONENT_VAR(n).name = #n; \
                                   COMPONENT_VAR(n).events = e; \
                                   m_components[g] = COMPONENT_VAR(n);

namespace REDasm {

VBComponents::Components VBComponents::m_components;

VBComponents::VBComponents()
{
}

const VBComponents::Component *VBComponents::get(GUID *guid)
{
    VBComponents::initComponents();

    std::string guidstring = guidString(guid);
    auto it = m_components.find(guidstring);

    if(it != m_components.end())
        return &(it->second);

    REDasm::log("Cannot find component " + guidstring);
    return NULL;
}

void VBComponents::initComponents()
{
    if(!m_components.empty())
        return;

    DECLARE_COMPONENT("{33AD5002-6699-11CF-B70C-00AA0060D393}", OLE,
                      EVENTS({ "Click", "DblClick", "DragDrop", "DragOver", "GotFocus",
                               "KeyDown", "KeyPress", "KeyUp", "LostFocus", "MouseDown",
                               "MouseMove", "MouseUp", "Resize", "Updated", "ObjectMove",
                               "Validate" }));

    DECLARE_COMPONENT("{33AD4FFA-6699-11CF-B70C-00AA0060D393}", Data,
                      EVENTS({ "Error", "Reposition", "Validate", "DragDrop", "DragOver",
                               "MouseDown", "MouseMove", "MouseUp", "Resize", "OLEDragOver",
                               "OLEDragDrop", "OLEGiveFeedback", "OLEStartDrag", "OLESetData",
                               "OLECompleteDrag" }));

    DECLARE_COMPONENT("{33AD4F2A-6699-11CF-B70C-00AA0060D393}", Timer,
                      EVENTS({ "Timer" }));

    DECLARE_COMPONENT("{33AD4F6A-6699-11CF-B70C-00AA0060D393}", Menu,
                      EVENTS({ "Click" }));

    DECLARE_COMPONENT("{33AD4EEA-6699-11CF-B70C-00AA0060D393}", Frame,
                      EVENTS({ "DragDrop", "DragOver", "MouseDown", "MouseMove", "MouseUp",
                               "Click", "DlbClick", "OLEDragOver", "OLEDragDrop", "OLEGiveFeedback",
                               "OLEStartDrag", "OLESetData", "OLECompleteDrag" }));

    DECLARE_COMPONENT("{33AD4EF2-6699-11CF-B70C-00AA0060D393}", CommandButton,
                      EVENTS({ "Click", "DragDrop", "DragOver", "GotFocus", "KeyDown", "KeyPress",
                               "KeyUp", "LostFocus", "MouseDown", "MouseMove", "MouseUp", "OLEDragOver",
                               "OLEDragDrop", "OLEGiveFeedback", "OLEStartDrag", "OLESetData", "OLECompleteDrag" }));

    DECLARE_COMPONENT("{33AD4F02-6699-11CF-B70C-00AA0060D393}", OptionButton,
                      EVENTS({ "Click", "DblClick", "DragDrop", "DragOver", "GotFocus", "KeyDown",
                               "KeyPress", "KeyUp", "LostFocus", "MouseDown", "MouseMove", "MouseUp",
                               "OLEDragOver", "OLEDragDrop", "OLEGiveFeedback", "OLEStartDrag", "OLESetData",
                               "OLECompleteDrag" }));

    DECLARE_COMPONENT("{33AD4EE2-6699-11CF-B70C-00AA0060D393}", TextBox,
                      EVENTS({ "Change", "DragDrop", "DragOver", "GotFocus", "KeyDown", "KeyPress",
                               "KeyUp", "LinkClose", "LinkError", "LinkOpen", "LostFocus", "LinkNotify",
                               "MouseDown", "MouseMove", "MouseUp", "Click", "DblClick", "OLEDragOver",
                               "OLEDragDrop", "OLEGiveFeedback", "OLEStartDrag", "OLESetData", "OLECompleteDrag",
                               "Validate" }));

    DECLARE_COMPONENT("{33AD4EFA-6699-11CF-B70C-00AA0060D393}", CheckBox,
                      EVENTS({ "Click", "DragDrop", "DragOver", "GotFocus", "KeyDown",
                               "KeyPress", "KeyUp", "LostFocus", "MouseDown", "MouseMove",
                               "MouseUp", "OLEDragOver", "OLEDragDrop", "OLEGiveFeedback",
                               "OLEStartDrag", "OLESetData", "OLECompleteDrag" }));

    DECLARE_COMPONENT("{33AD4F0A-6699-11CF-B70C-00AA0060D393}", ComboBox,
                      EVENTS({ "Change", "Click", "DblClick", "DragDrop", "DragOver", "DropDown",
                               "GotFocus", "KeyDown", "KeyPress", "KeyUp", "LostFocus", "OLEDragOver",
                               "OLEDragDrop", "OLEGiveFeedback", "OLEStartDrag", "OLESetData",
                               "OLECompleteDrag", "Scroll", "Validate" }));

    DECLARE_COMPONENT("{33AD4EDA-6699-11CF-B70C-00AA0060D393}", Label,
                      EVENTS({ "Change", "Click", "DblClick", "DragDrop", "DragOver", "LinkClose",
                               "LinkError", "LinkOpen", "MouseDown", "MouseMove", "MouseUp", "LinkNotify",
                               "OLEDragOver", "OLEDragDrop", "OLEGiveFeedback", "OLEStartDrag", "OLESetData",
                               "OLECompleteDrag" }));

    DECLARE_COMPONENT("{33AD4F3A-6699-11CF-B70C-00AA0060D393}", Form,
                      EVENTS({ "DragDrop", "DragOver", "LinkClose", "LinkError", "LinkExecute", "LinkOpen",
                               "Load", "Resize", "Unload", "QueryUnload", "Activate", "Deactivate", "Click",
                               "DblClick", "GotFocus", "KeyDown", "KeyPress", "KeyUp", "LostFocus", "MouseDown",
                               "MouseMove", "MouseUp", "Paint", "Initialize", "Terminate", "OLEDragOver", "OLEDragDrop",
                               "OLEGiveFeedback", "OLEStartDrag", "OLESetData", "OLECompleteDrag" }));

    DECLARE_COMPONENT("{33AD4F92-6699-11CF-B70C-00AA0060D393}", Image,
                      EVENTS({ "Click", "DlbClick", "DragDrop", "DragOver", "MouseDown", "MouseMove",
                               "MouseUp", "OLEDragOver", "OLEDragDrop", "OLEGiveFeedback", "OLEStartDrag",
                               "OLESetData", "OLECompleteDrag" }));

    DECLARE_COMPONENT("{33AD4ED2-6699-11CF-B70C-00AA0060D393}", Picture,
                      EVENTS({ "Change", "Click", "DblClick", "DragDrop", "DragOver", "GotFocus",
                               "KeyDown", "KeyPress", "KeyUp", "LinkClose", "LinkError", "LinkOpen",
                               "LostFocus", "MouseDown", "MouseMove", "MouseUp", "Paint", "LinkNotify",
                               "Resize", "OLEDragOver", "OLEDragDrop", "OLEGiveFeedback", "OLEStartDrag",
                               "OLESetData", "OLECompleteDrag", "Validate" }));

    DECLARE_COMPONENT("{33AD4F12-6699-11CF-B70C-00AA0060D393}", ListBox,
                      EVENTS({ "Click", "DblClick", "DragDrop", "DragOver", "GotFocus", "KeyDown",
                               "KeyPress", "KeyUp", "LostFocus", "MouseDown", "MouseMove", "MouseUp",
                               "OLEDragOver", "OLEDragDrop", "OLEGiveFeedback", "OLEStartDrag", "OLESetData",
                               "OLECompleteDrag", "Scroll", "ItemCheck", "Validate" }));

    DECLARE_COMPONENT("{33AD4F52-6699-11CF-B70C-00AA0060D393}", DriveListBox,
                      EVENTS({ "Change", "DragDrop", "DragOver", "GotFocus", "KeyDown", "KeyPress",
                               "KeyUp", "LostFocus", "OLEDragOver", "OLEDragDrop", "OLEGiveFeedback",
                               "OLEStartDrag", "OLESetDrive", "OLECompleteDrag", "Scroll", "Validate" }));

    DECLARE_COMPONENT("{33AD4F5A-6699-11CF-B70C-00AA0060D393}", DirListBox,
                      EVENTS({ "Change", "Click", "DragDrop", "DragOver", "GotFocus", "KeyDown",
                               "KeyPress", "KeyUp", "LostFocus", "MouseDown", "MouseMove", "MouseUp",
                               "OLEDragOver", "OLEDragDrop", "OLEGiveFeedback", "OLEStartDrag",
                               "OLESetData", "OLECompleteDrag", "Scroll", "Validate" }));

    DECLARE_COMPONENT("{33AD4F62-6699-11CF-B70C-00AA0060D393}", FileListBox,
                      EVENTS({ "Click", "DblClick", "DragDrop", "DragOver", "GotFocus", "KeyDown",
                               "KeyPress", "KeyUp", "LostFocus", "MouseDown", "MouseMove", "MouseUp",
                               "PathChange", "PatternChange" , "OLEDragOver", "OLEDragDrop", "OLEGiveFeedback",
                               "OLEStartDrag", "OLESetData", "OLECompleteDrag", "Scroll", "Validate" }));

    DECLARE_COMPONENT("{33AD4F22-6699-11CF-B70C-00AA0060D393}", VScrollBar,
                      EVENTS({ "Change", "DragDrop", "DragOver", "GotFocus", "KeyDown",
                               "KeyPress", "KeyUp", "LostFocus", "Scroll", "Validate" }));

    DECLARE_COMPONENT("{33AD4F1A-6699-11CF-B70C-00AA0060D393}", HScrollBar,
                      EVENTS({ "Change", "DragDrop", "DragOver", "GotFocus", "KeyDown",
                               "KeyPress", "KeyUp", "LostFocus", "Scroll", "Validate" }));
}

std::string VBComponents::guidString(GUID *guid)
{
    std::stringstream ss;

    ss << std::uppercase << std::hex << std::setfill('0');
    ss << std::setw(8) << guid->data1 << "-";
    ss << std::setw(4) << guid->data2 << "-";
    ss << std::setw(4) << guid->data3 << "-";

    for(size_t i = 0; i < sizeof(guid->data4); i++)
    {
        ss << std::setw(2) << static_cast<size_t>(guid->data4[i]);

        if(i == 1)
            ss << "-";
    }

    return "{" + ss.str() + "}";
}

} // namespace REDasm
